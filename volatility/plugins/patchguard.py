import struct

def rol(value, count):
    """A rotate-left instruction in Python"""
    
    for y in range(count):
        value *= 2
        if (value > 0xFFFFFFFFFFFFFFFF):
            value -= 0x10000000000000000
            value += 1
    return value

def bswap(value):
    """A byte-swap instruction in Python"""

    hi, lo = struct.unpack(">II", struct.pack("<Q", value))
    return (hi << 32) | lo 