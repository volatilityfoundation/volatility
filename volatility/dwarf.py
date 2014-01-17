# Volatility
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import re

class DWARFParser(object):
    """A parser for DWARF files."""

    # Nasty, but appears to parse the lines we need
    dwarf_header_regex = re.compile(
        r'<(?P<level>\d+)><(?P<statement_id>[0-9+]+)><(?P<kind>\w+)>')
    dwarf_key_val_regex = re.compile(
        '\s*(?P<keyname>\w+)<(?P<val>[^>]*)>')

    dwarf_header_regex2 = re.compile(r'<(?P<level>\d+)><(?P<statement_id>0x[0-9a-fA-F]+([+]0x[0-9a-fA-F]+)?)><(?P<kind>\w+)>')

    sz2tp = {8: 'long long', 4: 'int', 2: 'short', 1: 'char'}
    tp2vol = {
        '_Bool': 'unsigned char',
        'char': 'char',
        'float': 'float',
        'double': 'double',
        'long double': 'double',
        'int': 'int',
        'long int': 'long',
        'long long int': 'long long',
        'long long unsigned int': 'unsigned long long',
        'long unsigned int': 'unsigned long',
        'short int': 'short',
        'short unsigned int': 'unsigned short',
        'signed char': 'signed char',
        'unsigned char': 'unsigned char',
        'unsigned int': 'unsigned int',
        'sizetype' : 'unsigned long',
    }


    def __init__(self, data = None):
        self.current_level = -1
        self.name_stack = []
        self.id_to_name = {}
        self.all_vtypes = {}
        self.vtypes = {}
        self.enums = {}
        self.all_vars = {}
        self.vars = {}
        self.all_local_vars = []
        self.local_vars = []
        self.anons = 0
        self.base = 10

        if data:
            for line in data.splitlines():
                self.feed_line(line)

    def resolve(self, memb):
        """Lookup anonymous member and replace it with a well known one."""
        # Reference to another type
        if isinstance(memb, str) and memb.startswith('<'):
            if memb[1:3] == "0x":
                memb = "<0x" + memb[3:].lstrip('0')

            resolved = self.id_to_name[memb[1:]]

            return self.resolve(resolved)

        elif isinstance(memb, list):
            return [self.resolve(r) for r in memb]
        else:
            # Literal
            return memb

    def resolve_refs(self):
        """Replace references with types."""
        for v in self.vtypes:
            for m in self.vtypes[v][1]:
                self.vtypes[v][1][m] = self.resolve(self.vtypes[v][1][m])

        return self.vtypes

    def deep_replace(self, t, search, repl):
        """Recursively replace anonymous references."""
        if t == search:
            return repl

        elif isinstance(t, list):
            return [self.deep_replace(x, search, repl) for x in t]
        else:
            return t

    def get_deepest(self, t):
        if isinstance(t, list):
            if len(t) == 1:
                return t[0]
            else:
                for part in t:
                    res = self.get_deepest(part)
                    if res:
                        return res

                return None

        return None

    def base_type_name(self, data):
        """Replace references to base types."""
        if 'DW_AT_name' in data:
            return self.tp2vol[data['DW_AT_name'].strip('"')]
        else:
            sz = int(data['DW_AT_byte_size'], self.base)
            if data['DW_AT_encoding'] == 'DW_ATE_unsigned':
                return 'unsigned ' + self.sz2tp[sz]
            else:
                return self.sz2tp[sz]

    def feed_line(self, line):
        """Accepts another line from the input.

        A DWARF line looks like:
        <2><1442><DW_TAG_member> DW_AT_name<fs>  ...

        The header is level, statement_id, and kind followed by key value pairs.
        """
        # Does the header match?
        m = self.dwarf_header_regex.match(line)

        if self.dwarf_header_regex2.match(line):
            m = self.dwarf_header_regex2.match(line)
            self.base = 16

        if m:
            parsed = m.groupdict()
            parsed['data'] = {}
            # Now parse the key value pairs
            while m:
                i = m.end()
                m = self.dwarf_key_val_regex.search(line, i)
                if m:
                    d = m.groupdict()
                    parsed['data'][d['keyname']] = d['val']

            if parsed['kind'] in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
                self.process_variable(parsed['data'])
            else:
                self.process_statement(**parsed) #pylint: disable-msg=W0142

    def process_statement(self, kind, level, data, statement_id):
        """Process a single parsed statement."""
        new_level = int(level)
        if new_level > self.current_level:
            self.current_level = new_level
            self.name_stack.append([])
        elif new_level < self.current_level:
            self.name_stack = self.name_stack[:new_level + 1]
            self.current_level = new_level

        self.name_stack[-1] = [kind, statement_id]

        try:
            parent_kind, parent_name = self.name_stack[-2]
        except IndexError:
            parent_kind, parent_name = (None, None)

        if kind == 'DW_TAG_compile_unit':
            self.finalize()
            self.vtypes = {}
            self.vars = {}
            self.all_local_vars += self.local_vars
            self.local_vars = []
            self.id_to_name = {}

        elif kind == 'DW_TAG_structure_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id).strip('"')

            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'DW_AT_declaration' not in data:
                self.vtypes[name] = [ int(data['DW_AT_byte_size'], self.base), {} ]

        elif kind == 'DW_TAG_union_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id).strip('"')
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]
            self.vtypes[name] = [ int(data['DW_AT_byte_size'], self.base), {} ]

        elif kind == 'DW_TAG_array_type':
            self.name_stack[-1][1] = statement_id
            self.id_to_name[statement_id] = data['DW_AT_type']

        elif kind == 'DW_TAG_enumeration_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id).strip('"')
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'DW_AT_declaration' not in data:
                sz = int(data['DW_AT_byte_size'], self.base)
                self.enums[name] = [sz, {}]

        elif kind == 'DW_TAG_pointer_type':
            self.id_to_name[statement_id] = ['pointer', data.get('DW_AT_type', ['void'])]

        elif kind == 'DW_TAG_base_type':
            self.id_to_name[statement_id] = [self.base_type_name(data)]

        elif kind == 'DW_TAG_volatile_type':
            self.id_to_name[statement_id] = data.get('DW_AT_type', ['void'])

        elif kind == 'DW_TAG_const_type':
            self.id_to_name[statement_id] = data.get('DW_AT_type', ['void'])

        elif kind == 'DW_TAG_typedef':
            self.id_to_name[statement_id] = data['DW_AT_type']

        elif kind == 'DW_TAG_subroutine_type':
            self.id_to_name[statement_id] = ['void']         # Don't need these

        elif kind == 'DW_TAG_variable' and level == '1':
            if 'DW_AT_location' in data:
                split = data['DW_AT_location'].split()
                if len(split) > 1:
                    loc = int(split[1], 0)
                    self.vars[data['DW_AT_name']] = [loc, data['DW_AT_type']]

        elif kind == 'DW_TAG_subprogram':
            # IDEK
            pass

        elif kind == 'DW_TAG_member' and parent_kind == 'DW_TAG_structure_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id).strip('"')
            try:
                off = int(data['DW_AT_data_member_location'].split()[1])
            except:
                d = data['DW_AT_data_member_location']
                idx = d.find("(")

                if idx != -1:
                    d = d[:idx]

                off = int(d)

            if 'DW_AT_bit_size' in data and 'DW_AT_bit_offset' in data:
                full_size = int(data['DW_AT_byte_size'], self.base) * 8
                stbit = int(data['DW_AT_bit_offset'], self.base)
                edbit = stbit + int(data['DW_AT_bit_size'], self.base)
                stbit = full_size - stbit
                edbit = full_size - edbit
                stbit, edbit = edbit, stbit
                assert stbit < edbit
                memb_tp = ['BitField', dict(start_bit = stbit, end_bit = edbit)]
            else:
                memb_tp = data['DW_AT_type']

            self.vtypes[parent_name][1][name] = [off, memb_tp]

        elif kind == 'DW_TAG_member' and parent_kind == 'DW_TAG_union_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id).strip('"')
            self.vtypes[parent_name][1][name] = [0, data['DW_AT_type']]

        elif kind == 'DW_TAG_enumerator' and parent_kind == 'DW_TAG_enumeration_type':
            name = data['DW_AT_name'].strip('"')

            try:
                val = int(data['DW_AT_const_value'])
            except ValueError:
                val = int(data['DW_AT_const_value'].split('(')[0], self.base)

            self.enums[parent_name][1][name] = val

        elif kind == 'DW_TAG_subrange_type' and parent_kind == 'DW_TAG_array_type':
            if 'DW_AT_upper_bound' in data:
                try:
                    sz = int(data['DW_AT_upper_bound'])
                except ValueError:
                    try:
                        sz = int(data['DW_AT_upper_bound'].split('(')[0])
                    except ValueError:
                        # Give up
                        sz = 0
                sz += 1
            else:
                sz = 0

            tp = self.id_to_name[parent_name]
            self.id_to_name[parent_name] = ['array', sz, tp]
        else:
            pass
            #print "Skipping unsupported tag %s" % parsed['kind']


    def process_variable(self, data):
        """Process a local variable."""
        if ('DW_AT_name' in data and 'DW_AT_decl_line' in data and
            'DW_AT_type' in data):
            self.local_vars.append(
                (data['DW_AT_name'], int(data['DW_AT_decl_line'], self.base),
                 data['DW_AT_decl_file'].split()[1], data['DW_AT_type']))

    def finalize(self):
        """Finalize the output."""
        if self.vtypes:
            self.vtypes = self.resolve_refs()
            self.all_vtypes.update(self.vtypes)
        if self.vars:
            self.vars = dict(((k, self.resolve(v)) for k, v in self.vars.items()))
            self.all_vars.update(self.vars)
        if self.local_vars:
            self.local_vars = [ (name, lineno, decl_file, self.resolve(tp)) for
                                (name, lineno, decl_file, tp) in self.local_vars ]
            self.all_local_vars += self.local_vars

        # Get rid of unneeded unknowns (shades of Rumsfeld here)
        # Needs to be done in fixed point fashion
        changed = True
        while changed:
            changed = False
            s = set()
            for m in self.all_vtypes:
                for t in self.all_vtypes[m][1].values():
                    s.add(self.get_deepest(t))
            for m in self.all_vars:
                s.add(self.get_deepest(self.all_vars[m][1]))
            for v in list(self.all_vtypes):
                if v.startswith('__unnamed_') and v not in s:
                    del self.all_vtypes[v]
                    changed = True

        # Merge the enums into the types directly:
        for t in self.all_vtypes:
            for m in list(self.all_vtypes[t][1]):
                memb = self.all_vtypes[t][1][m]
                d = self.get_deepest(memb)
                if d in self.enums:
                    sz = self.enums[d][0]
                    vals = dict((v, k) for k, v in self.enums[d][1].items())
                    self.all_vtypes[t][1][m] = self.deep_replace(
                        memb, [d],
                        ['Enumeration', dict(target = self.sz2tp[sz], choices = vals)]
                    )

        return self.all_vtypes

    def print_output(self):
        self.finalize()
        print "linux_types = {"

        for t in self.all_vtypes:
            print "  '%s': [ %#x, {" % (t, self.all_vtypes[t][0])
            for m in sorted(self.all_vtypes[t][1], key = lambda m: self.all_vtypes[t][1][m][0]):
                print "    '%s': [%#x, %s]," % (m, self.all_vtypes[t][1][m][0], self.all_vtypes[t][1][m][1])
            print "}],"
        print "}"
        print
        print "linux_gvars = {"
        for v in sorted(self.all_vars, key = lambda v: self.all_vars[v][0]):
            print "  '%s': [%#010x, %s]," % (v, self.all_vars[v][0], self.all_vars[v][1])
        print "}"

if __name__ == '__main__':
    import sys
    dp = DWARFParser(open(sys.argv[1], "rb").read())
    dp.print_output()
