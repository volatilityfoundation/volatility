# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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

import volatility.win32.rawreg as rawreg
import volatility.win32.hive as hive
import volatility.win32.lsasecrets as lsasecrets
import volatility.win32.hashdump as hashdump
from Crypto.Hash import HMAC
from Crypto.Cipher import ARC4
from struct import unpack

def get_nlkm(secaddr, lsakey):
    return lsasecrets.get_secret_by_name(secaddr, 'NL$KM', lsakey)

def decrypt_hash(edata, nlkm, ch):
    hmac_md5 = HMAC.new(nlkm, ch)
    rc4key = hmac_md5.digest()

    rc4 = ARC4.new(rc4key)
    data = rc4.encrypt(edata)
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
    username = username.decode('utf-16-le')
    domain = dec_data[domain_off:domain_off + domain_len]
    domain = domain.decode('utf-16-le')
    domain_name = dec_data[domain_name_off:domain_name_off + domain_name_len]
    domain_name = domain_name.decode('utf-16-le')

    return (username, domain, domain_name, hashh)

def dump_hashes(sysaddr, secaddr):
    bootkey = hashdump.get_bootkey(sysaddr)
    if not bootkey:
        return None

    lsakey = lsasecrets.get_lsa_key(secaddr, bootkey)
    if not lsakey:
        return None

    nlkm = get_nlkm(secaddr, lsakey)
    if not nlkm:
        return None

    root = rawreg.get_root(secaddr)
    if not root:
        return None

    cache = rawreg.open_key(root, ["Cache"])
    if not cache:
        return None

    hashes = []
    for v in rawreg.values(cache):
        if v.Name == "NL$Control":
            continue

        data = v.obj_vm.read(v.Data, v.DataLength)

        (uname_len, domain_len, domain_name_len,
            enc_data, ch) = parse_cache_entry(data)

        # Skip if nothing in this cache entry
        if uname_len == 0:
            continue

        dec_data = decrypt_hash(enc_data, nlkm, ch)

        (username, domain, domain_name,
            hashh) = parse_decrypted_cache(dec_data, uname_len,
                    domain_len, domain_name_len)

        hashes.append((username, domain, domain_name, hashh))

    return hashes

def dump_memory_hashes(addr_space, config, syshive, sechive):
    sysaddr = hive.HiveAddressSpace(addr_space, config, syshive)
    secaddr = hive.HiveAddressSpace(addr_space, config, sechive)

    for (u, d, dn, hashh) in dump_hashes(sysaddr, secaddr):
        print "{0}:{1}:{2}:{3}".format(u.lower(), hashh.encode('hex'),
                                       d.lower(), dn.lower())

def dump_file_hashes(syshive_fname, sechive_fname):
    sysaddr = hive.HiveFileAddressSpace(syshive_fname)
    secaddr = hive.HiveFileAddressSpace(sechive_fname)

    for (u, d, dn, hashh) in dump_hashes(sysaddr, secaddr):
        print "{0}:{1}:{2}:{3}".format(u.lower(), hashh.encode('hex'),
                                       d.lower(), dn.lower())
