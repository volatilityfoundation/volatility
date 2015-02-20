__author__ = 'mike'

import volatility.utils as utils
import base64

class Hexdump(str):
    def __new__(cls, data, width = 16):
        string = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(data, width = width)])
        return str.__new__(cls, string)

class Base64(str):
    def __new__(cls, data):
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
