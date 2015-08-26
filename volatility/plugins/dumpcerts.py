# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Authors:
# Michael Hale Ligh <michael.ligh@mnin.org>
#
# Contributors/References:
#   ## Based on sslkeyfinder: http://www.trapkit.de/research/sslkeyfinder/
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

import os, sys, subprocess
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.procdump as procdump
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.plugins.malware.malfind as malfind
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Bytes

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

#--------------------------------------------------------------------------------
# object classes
#--------------------------------------------------------------------------------

class _X509_PUBLIC_CERT(obj.CType):
    """Class for x509 public key certificates"""
    
    @property
    def Size(self):
        """
        The certificate size (in bytes) is a product of this
        object's Size1 and Size2 members. 
        """
        return (self.Size1 << 8 & 0xFFFF) + self.Size2

    def object_as_string(self):
        """
        Get the object's data as a string. in this case its
        the certificate header and body. 
        """
        return self.obj_vm.zread(self.obj_offset, self.Size + 4)

    def is_valid(self):
        """
        This implements the check described in sslfinder:
        http://www.trapkit.de/research/sslkeyfinder/
        """

        if not obj.CType.is_valid(self):
            return False

        return self.Size < 0xFFF

    def as_openssl(self, file_name):
        """
        Represent this object as openssl-parsed certificate.

        Since OpenSSL does not accept DERs from STDIN, we 
        have to redirect it to a file first. 

        @param file_name: a file on disk where this object
        has been dumped. the caller should ensure that the
        file exists before calling this function. 
        """
        return subprocess.Popen(
                ['openssl', 'x509', '-in', file_name, '-inform', 'DER', '-text'], 
                stdout = subprocess.PIPE, 
                stderr = subprocess.PIPE
                ).communicate()[0]
        
class _PKCS_PRIVATE_CERT(_X509_PUBLIC_CERT):
    """Class for PKCS private key certificates"""
    
    def as_openssl(self, file_name):
        return subprocess.Popen(
                ['openssl', 'rsa', '-check', '-in', file_name, '-inform', 'DER', '-text'], 
                stdout = subprocess.PIPE, 
                stderr = subprocess.PIPE
                ).communicate()[0]

class SSLKeyModification(obj.ProfileModification):
    """Applies to all windows profiles (maybe linux?)"""

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):

        profile.vtypes.update({
            '_X509_PUBLIC_CERT': [ None, {
                'Size1': [ 0x2, ['unsigned char']], 
                'Size2': [ 0x3, ['unsigned char']], 
                }],
            '_PKCS_PRIVATE_CERT': [ None, {
                'Size1': [ 0x2, ['unsigned char']], 
                'Size2': [ 0x3, ['unsigned char']], 
                }],
            })

        profile.object_classes.update({
            '_X509_PUBLIC_CERT': _X509_PUBLIC_CERT, 
            '_PKCS_PRIVATE_CERT': _PKCS_PRIVATE_CERT, 
            })

# Inherit from ProcDump for access to the --dump-dir option
class DumpCerts(procdump.ProcDump):
    """Dump RSA private and public SSL keys"""

    # Wildcard signatures to scan for 
    rules = {}
    if has_yara:
        rules = yara.compile(sources = {
            'x509' : 'rule x509 {strings: $a = {30 82 ?? ?? 30 82 ?? ??} condition: $a}',
            'pkcs' : 'rule pkcs {strings: $a = {30 82 ?? ?? 02 01 00} condition: $a}',
            })

    # These signature names map to these data structures
    type_map = {
        'x509' : '_X509_PUBLIC_CERT', 
        'pkcs' : '_PKCS_PRIVATE_CERT',
    }

    def __init__(self, config, *args, **kwargs):
        procdump.ProcDump.__init__(self, config, *args, **kwargs)

        config.remove_option("UNSAFE")
        config.add_option("SSL", short_option = 's', 
                          default = False,
                          help = "Use OpenSSL for certificate parsing", action = "store_true")
        config.add_option("PHYSICAL", short_option = 'P',
                          default = False, 
                          help = "Scan across physical space (in deallocated/freed storage)",
                          action = "store_true")

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not has_yara:
            debug.error("You must install yara to use this plugin")

        if not self._config.DUMP_DIR:
            debug.error("You must supply a --dump-dir parameter")
        
        if self._config.PHYSICAL:
            # Find the FileAddressSpace
            while addr_space.__class__.__name__ != "FileAddressSpace":
                addr_space = addr_space.base 
            scanner = malfind.DiscontigYaraScanner(address_space = addr_space, 
                                                   rules = DumpCerts.rules)
            for hit, address in scanner.scan():
                cert = obj.Object(DumpCerts.type_map.get(hit.rule), 
                                            vm = scanner.address_space,
                                            offset = address, 
                                            )
                if cert.is_valid():
                    yield None, cert
        else:
            for process in self.filter_tasks(tasks.pslist(addr_space)):
                scanner = malfind.VadYaraScanner(task = process, rules = DumpCerts.rules)
                for hit, address in scanner.scan():
                    cert = obj.Object(DumpCerts.type_map.get(hit.rule), 
                                            vm = scanner.address_space,
                                            offset = address, 
                                            )
                    if cert.is_valid():
                        yield process, cert

    def get_parsed_fields(self, openssl, fields = ["O", "OU"]):
        """
        Get fields from the parsed openssl output. 

        @param openssl: the output of an openssl command

        @param fields: fields of the SSL public or private
        key certificate that you want to get.

        @returns: a tuple of the field found and the field value.
        
        """
        for line in openssl.split("\n"):
            if "Subject:" in line:
                line = line[line.find("Subject:") + 10:]
                pairs = line.split(",")
                for pair in pairs:
                    try:
                        val, var = pair.split("=")
                    except ValueError:
                        continue
                    val = val.strip()
                    var = var.strip()
                    if val in fields:
                        yield (val, var)

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                       ("Process", str),
                       ("Address", Address),
                       ("Type", str),
                       ("Length", int),
                       ("File", str),
                       ("Subject", str),
                       ("Cert", Bytes)],
                        self.generator(data))

    def generator(self, data):
        for process, cert in data:
            if cert.obj_name == "_X509_PUBLIC_CERT":
                ext = ".crt"
            else:
                ext = ".key"

            if process:
                file_name = "{0}-{1:x}{2}".format(process.UniqueProcessId, 
                                                  cert.obj_offset, ext)
            else:
                file_name = "phys.{0:x}{1}".format(cert.obj_offset, ext)

            full_path = os.path.join(self._config.DUMP_DIR, file_name)

            with open(full_path, "wb") as cert_file:
                cert_file.write(cert.object_as_string())

            parsed_subject = ""
            if self._config.SSL:
                openssl_string = cert.as_openssl(full_path)
                parsed_subject = '/'.join([v[1] for v in self.get_parsed_fields(openssl_string)])

            yield (0, [int(process.UniqueProcessId if process else -1),
                       str(process.ImageFileName if process else "-"),
                       Address(cert.obj_offset),
                       str(cert.obj_name),
                       int(cert.Size),
                       str(file_name),
                       str(parsed_subject),
                       Bytes(cert.object_as_string())])


    def render_text(self, outfd, data):

        self.table_header(outfd, [("Pid", "8"), 
                                  ("Process", "16"), 
                                  ("Address", "[addrpad]"), 
                                  ("Type", "20"), 
                                  ("Length", "8"), 
                                  ("File", "24"), 
                                  ("Subject", "")])

        for process, cert in data:
            if cert.obj_name == "_X509_PUBLIC_CERT":
                ext = ".crt"
            else:
                ext = ".key"

            if process:
                file_name = "{0}-{1:x}{2}".format(process.UniqueProcessId, 
                                                  cert.obj_offset, ext)
            else:
                file_name = "phys.{0:x}{1}".format(cert.obj_offset, ext)

            full_path = os.path.join(self._config.DUMP_DIR, file_name)

            with open(full_path, "wb") as cert_file:
                cert_file.write(cert.object_as_string())

            parsed_subject = ""
            if self._config.SSL:
                openssl_string = cert.as_openssl(full_path)
                parsed_subject = '/'.join([v[1] for v in self.get_parsed_fields(openssl_string)])

            self.table_row(outfd, 
                    process.UniqueProcessId if process else "-", 
                    process.ImageFileName if process else "-", 
                    cert.obj_offset, cert.obj_name, 
                    cert.Size, file_name, parsed_subject)
