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

#pylint: disable-msg=C0111

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      bdolangavitt@wesleyan.edu
"""

import struct
import volatility.win32.rawreg as rawreg
import volatility.win32.hive as hive
import volatility.win32.hashdump as hashdump
from Crypto.Hash import MD5
from Crypto.Cipher import ARC4, DES

def get_lsa_key(secaddr, bootkey):
    if not bootkey:
        return None

    root = rawreg.get_root(secaddr)
    if not root:
        return None

    enc_reg_key = rawreg.open_key(root, ["Policy", "PolSecretEncryptionKey"])
    if not enc_reg_key:
        return None

    enc_reg_value = enc_reg_key.ValueList.List.dereference()[0]
    if not enc_reg_value:
        return None

    obf_lsa_key = secaddr.read(enc_reg_value.Data,
            enc_reg_value.DataLength)
    if not obf_lsa_key:
        return None

    md5 = MD5.new()
    md5.update(bootkey)
    for _i in range(1000):
        md5.update(obf_lsa_key[60:76])
    rc4key = md5.digest()

    rc4 = ARC4.new(rc4key)
    lsa_key = rc4.decrypt(obf_lsa_key[12:60])

    return lsa_key[0x10:0x20]

def decrypt_secret(secret, key):
    """Python implementation of SystemFunction005.

    Decrypts a block of data with DES using given key.
    Note that key can be longer than 7 bytes."""
    decrypted_data = ''
    j = 0   # key index
    for i in range(0, len(secret), 8):
        enc_block = secret[i:i + 8]
        block_key = key[j:j + 7]
        des_key = hashdump.str_to_key(block_key)

        des = DES.new(des_key, DES.MODE_ECB)
        decrypted_data += des.decrypt(enc_block)

        j += 7
        if len(key[j:j + 7]) < 7:
            j = len(key[j:j + 7])

    (dec_data_len,) = struct.unpack("<L", decrypted_data[:4])
    return decrypted_data[8:8 + dec_data_len]

def get_secret_by_name(secaddr, name, lsakey):
    root = rawreg.get_root(secaddr)
    if not root:
        return None

    enc_secret_key = rawreg.open_key(root, ["Policy", "Secrets", name, "CurrVal"])
    if not enc_secret_key:
        return None

    enc_secret_value = enc_secret_key.ValueList.List.dereference()[0]
    if not enc_secret_value:
        return None

    enc_secret = secaddr.read(enc_secret_value.Data,
            enc_secret_value.DataLength)
    if not enc_secret:
        return None

    return decrypt_secret(enc_secret[0xC:], lsakey)

def get_secrets(sysaddr, secaddr):
    root = rawreg.get_root(secaddr)
    if not root:
        return None

    bootkey = hashdump.get_bootkey(sysaddr)
    lsakey = get_lsa_key(secaddr, bootkey)
    if not bootkey or not lsakey:
        return None

    secrets_key = rawreg.open_key(root, ["Policy", "Secrets"])
    if not secrets_key:
        return None

    secrets = {}
    for key in rawreg.subkeys(secrets_key):
        sec_val_key = rawreg.open_key(key, ["CurrVal"])
        if not sec_val_key:
            continue

        enc_secret_value = sec_val_key.ValueList.List.dereference()[0]
        if not enc_secret_value:
            continue

        enc_secret = secaddr.read(enc_secret_value.Data,
                enc_secret_value.DataLength)
        if not enc_secret:
            continue

        secret = decrypt_secret(enc_secret[0xC:], lsakey)
        secrets[key.Name] = secret

    return secrets

def get_memory_secrets(addr_space, config, syshive, sechive):
    sysaddr = hive.HiveAddressSpace(addr_space, config, syshive)
    secaddr = hive.HiveAddressSpace(addr_space, config, sechive)

    return get_secrets(sysaddr, secaddr)

def get_file_secrets(sysfile, secfile):
    sysaddr = hive.HiveFileAddressSpace(sysfile)
    secaddr = hive.HiveFileAddressSpace(secfile)

    return get_secrets(sysaddr, secaddr)
