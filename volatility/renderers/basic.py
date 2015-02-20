__author__ = 'mike'

import volatility.utils as utils
import base64, binascii

class Binary(str):
    def __new__(cls, data):
        if data == None:
            return str.__new__(cls, "-")
        return str(data)

class Hexdump(str):
    """String class to allow us to output binary data in hexdump format"""
    def __new__(cls, data, width = 16):
        if data == None:
            return str.__new__(cls, "-")
        string = "\n".join(["{0:#010x}  {1:<{width}}  {2}".format(o, h, ''.join(c), width = width * 3) for o, h, c in utils.Hexdump(data, width = width)])
        return str.__new__(cls, string)

class Base64(Binary):
    """String class to allow us to base64 encode binary data"""
    def __new__(cls, data):
        if data == None:
            return str.__new__(cls, "-")
        string = base64.b64encode(data)
        return str.__new__(cls, string)

class Address(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""
    def __new__(cls, number):
        return long.__new__(cls, number)


class Address64(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return long.__new__(cls, number)


class Hex(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return long.__new__(cls, number)


class Renderer(object):
    def render(self, outfd, grid):
        """Renders the content, ideally to outfd, but this is not strictly necessary"""
