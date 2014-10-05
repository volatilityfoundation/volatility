__author__ = 'mike'


class Address(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""
    def __new__(cls, number):
        return long.__new__(cls, number)


class Address64(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return long.__new__(cls, number)


class Hex(int):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return int.__new__(cls, number)


class Renderer(object):
    def render(self, outfd, grid):
        """Renders the content, ideally to outfd, but this is not strictly necessary"""
