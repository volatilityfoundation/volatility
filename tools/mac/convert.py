import os, sys, re

class DWARFParser(object):
    """A parser for DWARF files."""

    # Nasty, but appears to parse the lines we need
    dwarf_header_regex = re.compile(
        r'<(?P<level>\d+)><(?P<statement_id>[0-9+]+)><(?P<kind>\w+)>')
    dwarf_key_val_regex = re.compile(
        '\s*(?P<keyname>\w+)<(?P<val>[^>]*)>')

    sz2tp = {8: 'long long', 4: 'long', 2: 'short', 1: 'char'}
    tp2vol = {
        'bool' : 'int',
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
        'unsigned short' : 'unsigned short',
        'short' : 'short',
        'signed char': 'signed char',
        'unsigned char': 'unsigned char',
        'unsigned int': 'unsigned int',
    }

    def __init__(self):
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

    def resolve(self, memb):
        """Lookup anonymouse member and replace it with a well known one."""
        # Reference to another type
        if isinstance(memb, str) and memb.startswith('<'):

            try:
                resolved = self.id_to_name[memb[1:]]
            except:
                resolved = 0 

            ret = self.resolve(resolved)

        elif isinstance(memb, list):
            ret = [self.resolve(r) for r in memb]
        else:
            # Literal
            ret = memb

        return ret

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
        else: return t

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
        if 'AT_name' in data:
            return self.tp2vol[data['AT_name']]
        else:
            sz = int(data['AT_byte_size'])
            if data['AT_encoding'] == 'ATE_unsigned':
                return 'unsigned ' + self.sz2tp[sz]
            else:
                return self.sz2tp[sz]

    def feed_line(self, line):

        line = line.replace("\n", "")

        # Does the header match?
        m = self.dwarf_header_regex.match(line)
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

            if parsed['kind'] in ('TAG_formal_parameter','TAG_variable'):
                self.process_variable(parsed['data'])
            else:
                self.process_statement(**parsed)
        #else:
        #    print "line %s does not match" % line.strip()

    def process_statement(self, kind, level, data, statement_id):
        """Process a single parsed statement."""
        new_level = int(level)
        if new_level > self.current_level:
            self.current_level = new_level
            self.name_stack.append([])
        elif new_level < self.current_level:
            self.name_stack = self.name_stack[:new_level+1]
            self.current_level = new_level

        self.name_stack[-1] = [kind, statement_id]

        try:
            parent_kind, parent_name = self.name_stack[-2]
        except IndexError:
            parent_kind, parent_name = (None, None)

        if kind == 'TAG_compile_unit':
            self.finalize()
            self.vtypes = {}
            self.vars = {}
            self.all_local_vars += self.local_vars
            self.local_vars = []
            self.id_to_name = {}

        elif kind == 'TAG_structure_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'AT_declaration' not in data:
                try:
                    self.vtypes[name] = [ int(data['AT_byte_size']), {} ]
                except:
                    self.vtypes[name] = [ int(data['AT_byte_size'], 16), {} ]

        elif kind == 'TAG_class_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)

            name = name + "_class"

            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            
            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'AT_declaration' not in data:
                try:
                    self.vtypes[name] = [ int(data['AT_byte_size']), {} ]
                except:
                    self.vtypes[name] = [ int(data['AT_byte_size'], 16), {} ]

        elif kind == 'TAG_union_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]
            try:
                self.vtypes[name] = [ int(data['AT_byte_size']), {} ]
            except:
                self.vtypes[name] = [ 0, {} ]

        elif kind == 'TAG_array_type':
            self.name_stack[-1][1] = statement_id
            self.id_to_name[statement_id] = data['AT_type']

        elif kind == 'TAG_enumeration_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'AT_declaration' not in data:
                try:
                    sz = int(data['AT_byte_size'])
                except:
                    sz = 0
                self.enums[name] = [sz, {}]

        elif kind == 'TAG_pointer_type':
            self.id_to_name[statement_id] = ['pointer', data.get('AT_type', ['void'])]

        elif kind == 'TAG_base_type':
            self.id_to_name[statement_id] = [self.base_type_name(data)]

        elif kind == 'TAG_volatile_type':
            self.id_to_name[statement_id] = data.get('AT_type', ['void'])

        elif kind == 'TAG_const_type':
            self.id_to_name[statement_id] = data.get('AT_type', ['void'])

        elif kind == 'TAG_typedef':
            try:
                self.id_to_name[statement_id] = data['AT_type']
            except:
                self.id_to_name[statement_id] = ['void']

        elif kind == 'TAG_subroutine_type':
            self.id_to_name[statement_id] = ['void']         # Don't need these

        elif kind == 'TAG_variable' and level == '1':
            if 'AT_location' in data:
                split = data['AT_location'].split()
                if len(split) > 1:
                    loc = int(split[1], 0)
                    self.vars[data['AT_name']] = [loc, data['AT_type']]

        elif kind == 'TAG_subprogram':
            # IDEK
            pass

        elif kind == 'TAG_member' and parent_kind == 'TAG_structure_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            off = int(data['AT_data_member_location'])

            if 'AT_bit_size' in data and 'AT_bit_offset' in data:
                full_size = int(data['AT_byte_size'])*8
                stbit = int(data['AT_bit_offset'])
                edbit = stbit + int(data['AT_bit_size'])
                stbit = full_size - stbit
                edbit = full_size - edbit
                stbit, edbit = edbit, stbit
                assert stbit < edbit
                memb_tp = ['BitField', dict(start_bit = stbit, end_bit = edbit)]
            else:
                memb_tp = data['AT_type']

            self.vtypes[parent_name][1][name] = [off, memb_tp]

        elif kind == 'TAG_member' and parent_kind == 'TAG_class_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)

            try:
                off = int(data['AT_data_member_location'])
            except:
                off = 0

            if 'AT_bit_size' in data and 'AT_bit_offset' in data:
                full_size = int(data['AT_byte_size'])*8
                stbit = int(data['AT_bit_offset'])
                edbit = stbit + int(data['AT_bit_size'])
                stbit = full_size - stbit
                edbit = full_size - edbit
                stbit, edbit = edbit, stbit
                assert stbit < edbit
                memb_tp = ['BitField', dict(start_bit = stbit, end_bit = edbit)]
            else:
                memb_tp = data['AT_type']

            self.vtypes[parent_name][1][name] = [off, memb_tp]

        elif kind == 'TAG_member' and parent_kind == 'TAG_union_type':
            name = data.get('AT_name', "__unnamed_%s" % statement_id)
            self.vtypes[parent_name][1][name] = [0, data['AT_type']]

        elif kind == 'TAG_enumerator' and parent_kind == 'TAG_enumeration_type':
            name = data['AT_name']

            try:
                val = int(data['AT_const_value'])
            except ValueError:
                val = int(data['AT_const_value'].split('(')[0])

            self.enums[parent_name][1][name] = val

        elif kind == 'TAG_subrange_type' and parent_kind == 'TAG_array_type':
            if 'AT_upper_bound' in data:
                try:
                    sz = int(data['AT_upper_bound'])
                except ValueError:
                    try:
                        sz = int(data['AT_upper_bound'].split('(')[0])
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
            #if kind != "NULL":
            #    print "Skipping unsupported tag %s" % kind


    def process_variable(self, data):
        return
        """Process a local variable."""
        if ('AT_name' in data and 'AT_decl_line' in data and
            'AT_type' in data):
            self.local_vars.append(
                (data['AT_name'], int(data['AT_decl_line']),
                 data['AT_decl_file'].split()[1], data['AT_type']) )

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
                        ['Enumeration', dict(target = 'int', choices = vals)]
                    )

        return self.all_vtypes

    def print_output(self):
        self.finalize()
        print "mac_types = {"

        for t in self.all_vtypes:
            print "  '%s': [ %#x, {" % (t, self.all_vtypes[t][0])
            for m in sorted(self.all_vtypes[t][1], key=lambda m: self.all_vtypes[t][1][m][0]):
                print "    '%s': [%#x, %s]," % (m, self.all_vtypes[t][1][m][0], self.all_vtypes[t][1][m][1])
            print "}],"
        print "}"
        print
        print "mac_gvars = {"
        for v in sorted(self.all_vars, key=lambda v: self.all_vars[v][0]):
            print "  '%s': [%#010x, %s]," % (v, self.all_vars[v][0], self.all_vars[v][1])
        print "}"

def parse_dwarf():

    """Parse the dwarf file."""
    parser = DWARFParser()

    for line in open(sys.argv[1],"r").readlines():
        parser.feed_line(line)

    parser.print_output()

    #for k in parser.wtf:
    #    print k
                
def write_line(outfile, level, id, name):

    outfile.write("<%s><%s><%s> " % (level, id, name))

def convert_file(mac_file, outfile):

    '''
    5 spaces, level 1
    0x00000428:     TAG_typedef [15]
    
    9 spaces, level 2, (struct member)
    0x00000446:         TAG_member [30]

    at
    AT_type( {0x0000008b}
    '''

    level1_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{5}(\w+)\s')
    level2_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{9}(\w+)\s')
    level3_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{13}(\w+)\s')
    level4_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{17}(\w+)\s')
    level5_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{21}(\w+)\s')
    level6_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{25}(\w+)\s')
    level7_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{29}(\w+)\s')
    level8_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{33}(\w+)\s')
    level9_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{37}(\w+)\s')
    level10_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{41}(\w+)\s')
    level11_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{45}(\w+)\s')
    level12_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{49}(\w+)\s')
    level13_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{53}(\w+)\s')
    level14_re = re.compile(r'^(0x[0-9a-fA-F]+):\s{57}(\w+)\s')
    
    at_re     = re.compile(r'^\s+(\w+)\((.+)')

    level = 0
    dontbreak = 0

    for line in mac_file.readlines():

        if len(line) < 2:
            outfile.write("\n")
            level = 0
            continue

        if line.find("-------------") != -1:
            level = 0
            continue
            
        if line.find("File:") != -1:
            level = 0
            continue

        if line.find(".debug_info") != -1:
            level = 0
            continue
        
        if line.find("Compile Unit:") != -1:
            level = 0
            continue

        if line.find("TAG_compile_unit") != -1:
            outfile.write("<1><999999999999999><TAG_compile_unit> ")
            level = 1 
            continue

        # new declaration
        if level == 0:
            m = level1_re.match(line)
            t = level2_re.match(line)
            r = level3_re.match(line)
            f = level4_re.match(line)
            z = level5_re.match(line)
            s = level6_re.match(line)
            y = level7_re.match(line)
            b = level8_re.match(line)
            j = level9_re.match(line)
            a = level10_re.match(line)
            c = level11_re.match(line)
            d = level12_re.match(line)
            e = level13_re.match(line)
            g = level14_re.match(line)            

            if m:
                (id, name) = m.groups()
                id = "%d" % int(id, 16)
                level = 1

                write_line(outfile, 1, id, name)

            elif t:
                (id, name) = t.groups()
                id = "%d" % int(id, 16)
                level = 1
                
                write_line(outfile, 2, id, name)
            
            elif r:
                (id, name) = r.groups()
                id = "%d" % int(id, 16)           
                level = 1
                
                write_line(outfile, 3, id, name)

            elif f:
                (id, name) = f.groups()
                id = "%d" % int(id, 16)
                level = 1

                write_line(outfile, 4, id, name)

            elif z:
                (id, name) = z.groups()    
                level = 1
                id = "%d" % int(id, 16)

                write_line(outfile, 5, id, name)
    
            elif s:
                (id, name) = s.groups()
                id = "%d" % int(id, 16)
                level = 1
            
                write_line(outfile, 6, id, name)

            elif y:
                (id, name) = y.groups()
                id = "%d" % int(id, 16)
                level = 1
           
                write_line(outfile, 7, id, name)
            
            elif b:
                (id, name) = b.groups()
                id = "%d" % int(id, 16)
                level = 1

                write_line(outfile, 8, id, name)

            elif j:
                (id, name) = j.groups()
                id = "%d" % int(id, 16)
                level = 1

                write_line(outfile, 9, id, name)

            elif a:
                (id, name) = a.groups()
                id = "%d" % int(id, 16)
                level = 1
                
                write_line(outfile, 10, id, name)

            elif c:
                (id, name) = c.groups()
                id = "%d" % int(id, 16)
                level = 1
                
                write_line(outfile, 11, id, name)

            elif d:
                (id, name) = d.groups()
                id = "%d" % int(id, 16)
                level = 1
                
                write_line(outfile, 12, id, name)

            elif e:
                (id, name) = e.groups()
                id = "%d" % int(id, 16)
                level = 1
                
                write_line(outfile, 13, id, name)

            elif g:
                (id, name) = g.groups()
                id = "%d" % int(id, 16)
                level = 1
        
                write_line(outfile, 14, id, name)

            else:
                print "State machine broken! level 0! %s" % line
                sys.exit(1)

        # can either be: new declaration
        #                AT_xxxx
        #                blank
        elif level == 1:
                        
            m = level2_re.match(line)
            a = at_re.match(line)
            if m:
                (id, name) = m.groups()
                id = "%d" % int(id, 16)
                level = 2
                
                # <1><41><DW_TAG_structure_type>
                outfile.write("<%s><%s><%s> " % (level, id, name))

            elif a:
                (name, val) = a.groups()

                #DW_AT_byte_size<2> 

                val = val[:-2]

                if val[0] == " ":
                    val = val[1:]

                # remove the " surround type name
                if name == "AT_name":
                    val = val[1:-1]

                if name == "AT_const_value":
                    ents = val.split()
                    if len(ents) > 1:
                        ents = ents[1:]
                        try:
                            val = "%d" % int("0x" + "".join([x for x in ents]),16)
                        except:
                            val = "Bad const list val"
                    else:
                        try:
                            val = "%d" % int(val, 16)
                        except:
                            val = "Bad const value"

                if name in ["AT_byte_size", "AT_bit_offset", "AT_bit_size", "AT_upper_bound"]:
                    val = "%d" % int(val, 16)

                if name == "AT_data_member_location":
                    # skip +
                    val = val[1:]
            
                if name == "AT_type":
                    # convert {0x00000550} ( queue_chain_t )
                    # to      decimal of int

                    val = val.split()[0]
                    val = val[1:-1]
                    val = "<%d>" % int(val, 16)

                outfile.write("%s<%s> " % (name, val))
                outfile.flush()
            #else:
                #print "State machine broken! level %d!%s" % (level, line)
                #sys.exit(1)

def main():

    if len(sys.argv) == 3:

        print "converting file"
        mac_file = open(sys.argv[1], "r")
        outfile = open(sys.argv[2], "w")
        convert_file(mac_file, outfile)
        outfile.close()

    else:
        parse_dwarf()     

if __name__ == "__main__":
    main()
        
 
