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
import volatility.obj as obj
import volatility.win32.rawreg as rawreg
import volatility.win32.hive as hive
import volatility.win32.hashdump as hashdump
from Crypto.Hash import MD5, SHA256
from Crypto.Cipher import ARC4, DES, AES

def decrypt_aes(secret, key):
    """
    Based on code from http://lab.mediaservice.net/code/cachedump.rb
    """
    sha = SHA256.new()
    sha.update(key)
    for _i in range(1, 1000 + 1):
        sha.update(secret[28:60])
    aeskey = sha.digest()

    data = ""
    for i in range(60, len(secret), 16):
        aes = AES.new(aeskey, AES.MODE_CBC, '\x00' * 16)
        buf = secret[i : i + 16]
        if len(buf) < 16:
            buf += (16 - len(buf)) * "\00"
        data += aes.decrypt(buf)

    return data

def get_lsa_key(addr_space, secaddr, bootkey):
    if not bootkey:
        return None

    root = rawreg.get_root(secaddr)
    if not root:
        return None

    volmag = obj.VolMagic(addr_space)
    enc_reg_key = rawreg.open_key(root, ["Policy", volmag.PolicyKey.v()])
    if not enc_reg_key:
        return None

    enc_reg_value = enc_reg_key.ValueList.List.dereference()[0]
    if not enc_reg_value:
        return None

    obf_lsa_key = secaddr.read(enc_reg_value.Data,
            enc_reg_value.DataLength)
    if not obf_lsa_key:
        return None

    if addr_space.profile.metadata.get('major', 0) == 5:
        md5 = MD5.new()
        md5.update(bootkey)
        for _i in range(1000):
            md5.update(obf_lsa_key[60:76])
        rc4key = md5.digest()

        rc4 = ARC4.new(rc4key)
        lsa_key = rc4.decrypt(obf_lsa_key[12:60])
        lsa_key = lsa_key[0x10:0x20]
    else:
        lsa_key = decrypt_aes(obf_lsa_key, bootkey)
        lsa_key = lsa_key[68:100]

    return lsa_key

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
        enc_block = enc_block + "\x00" * int(abs(8 - len(enc_block)) % 8)
        decrypted_data += des.decrypt(enc_block)

        j += 7
        if len(key[j:j + 7]) < 7:
            j = len(key[j:j + 7])

    (dec_data_len,) = struct.unpack("<L", decrypted_data[:4])
    return decrypted_data[8:8 + dec_data_len]

def get_secret_by_name(addr_space, secaddr, name, lsakey):
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

    if addr_space.profile.metadata.get('major', 0) == 5:
        secret = decrypt_secret(enc_secret[0xC:], lsakey)
    else:
        secret = decrypt_aes(enc_secret, lsakey)
    return secret

def get_secrets(addr_space, sysaddr, secaddr):
    root = rawreg.get_root(secaddr)
    if not root:
        return None

    bootkey = hashdump.get_bootkey(sysaddr)
    lsakey = get_lsa_key(addr_space, secaddr, bootkey)
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

        if addr_space.profile.metadata.get('major', 0) == 5:
            secret = decrypt_secret(enc_secret[0xC:], lsakey)
        else:
            secret = decrypt_aes(enc_secret, lsakey)
        secrets[key.Name] = secret

    return secrets

def get_memory_secrets(addr_space, config, syshive, sechive):
    if syshive != None and sechive != None:
        sysaddr = hive.HiveAddressSpace(addr_space, config, syshive)
        secaddr = hive.HiveAddressSpace(addr_space, config, sechive)

        return get_secrets(addr_space, sysaddr, secaddr)
    return None

'''
def get_file_secrets(sysfile, secfile):
    sysaddr = hive.HiveFileAddressSpace(sysfile)
    secaddr = hive.HiveFileAddressSpace(secfile)
    return get_secrets(sysaddr, secaddr)
'''
