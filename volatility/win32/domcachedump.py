# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      bdolangavitt@wesleyan.edu
"""

#pylint: disable-msg=C0111

import volatility.obj as obj
import volatility.win32.rawreg as rawreg
import volatility.win32.hive as hive
import volatility.win32.lsasecrets as lsasecrets
import volatility.win32.hashdump as hashdump
from Crypto.Hash import HMAC
from Crypto.Cipher import ARC4, AES
from struct import unpack

def get_nlkm(addr_space, secaddr, lsakey):
    return lsasecrets.get_secret_by_name(addr_space, secaddr, 'NL$KM', lsakey)

def decrypt_hash(edata, nlkm, ch, xp = True):
    if xp:
        hmac_md5 = HMAC.new(nlkm, ch)
        rc4key = hmac_md5.digest()

        rc4 = ARC4.new(rc4key)
        data = rc4.encrypt(edata)
    else:
        # based on  Based on code from http://lab.mediaservice.net/code/cachedump.rb
        aes = AES.new(nlkm[16:32], AES.MODE_CBC, ch)
        data = ""
        for i in range(0, len(edata), 16):
            buf = edata[i : i + 16]
            if len(buf) < 16:
                buf += (16 - len(buf)) * "\00"
                data += aes.decrypt(buf) 
    return data

def parse_cache_entry(cache_data):
    (uname_len, domain_len) = unpack("<HH", cache_data[:4])
    (domain_name_len,) = unpack("<H", cache_data[60:62])
    ch = cache_data[64:80]
    enc_data = cache_data[96:]
    return (uname_len, domain_len, domain_name_len, enc_data, ch)

def parse_decrypted_cache(dec_data, uname_len,
        domain_len, domain_name_len):
    uname_off = 72
    pad = 2 * ((uname_len / 2) % 2)
    domain_off = uname_off + uname_len + pad
    pad = 2 * ((domain_len / 2) % 2)
    domain_name_off = domain_off + domain_len + pad

    hashh = dec_data[:0x10]
    username = dec_data[uname_off:uname_off + uname_len]
    username = username.decode('utf-16-le', 'replace')
    domain = dec_data[domain_off:domain_off + domain_len]
    domain = domain.decode('utf-16-le', 'replace')
    domain_name = dec_data[domain_name_off:domain_name_off + domain_name_len]
    domain_name = domain_name.decode('utf-16-le', 'replace')

    return (username, domain, domain_name, hashh)

def dump_hashes(addr_space, sysaddr, secaddr):
    bootkey = hashdump.get_bootkey(sysaddr)
    if not bootkey:
        return []

    lsakey = lsasecrets.get_lsa_key(addr_space, secaddr, bootkey)
    if not lsakey:
        return []

    nlkm = get_nlkm(addr_space, secaddr, lsakey)
    if not nlkm:
        return []

    root = rawreg.get_root(secaddr)
    if not root:
        return []

    cache = rawreg.open_key(root, ["Cache"])
    if not cache:
        return []

    xp = addr_space.profile.metadata.get('major', 0) == 5
    hashes = []
    for v in rawreg.values(cache):
        if v.Name == "NL$Control":
            continue

        data = v.obj_vm.read(v.Data, v.DataLength)
        if data == None:
            continue

        (uname_len, domain_len, domain_name_len,
            enc_data, ch) = parse_cache_entry(data)

        # Skip if nothing in this cache entry
        if uname_len == 0:
            continue

        dec_data = decrypt_hash(enc_data, nlkm, ch, xp)

        (username, domain, domain_name,
            hashh) = parse_decrypted_cache(dec_data, uname_len,
                    domain_len, domain_name_len)

        hashes.append((username, domain, domain_name, hashh))

    return hashes

def dump_memory_hashes(addr_space, config, syshive, sechive):
    hashes = []
    if syshive != None and sechive != None:
        sysaddr = hive.HiveAddressSpace(addr_space, config, syshive)
        secaddr = hive.HiveAddressSpace(addr_space, config, sechive)
        hashes = dump_hashes(addr_space, sysaddr, secaddr)

    if hashes == []:
        return obj.NoneObject("Unable to find hashes")
    else:
        result = []
        for (u, d, dn, hashh) in hashes:
            result.append("{0}:{1}:{2}:{3}".format(u.encode('utf-8', 'ignore').lower(), hashh.encode('hex'),
                                       d.encode('utf-8', 'ignore').lower(), dn.encode('utf-8', 'ignore').lower()))
        return result
'''
# I don't think this is used anywhere
def dump_file_hashes(syshive_fname, sechive_fname):
    sysaddr = hive.HiveFileAddressSpace(syshive_fname)
    secaddr = hive.HiveFileAddressSpace(sechive_fname)

    for (u, d, dn, hashh) in dump_hashes(addr_space, sysaddr, secaddr):
        print "{0}:{1}:{2}:{3}".format(u.lower(), hashh.encode('hex'),
                                       d.lower(), dn.lower())
'''
