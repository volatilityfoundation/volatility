import math
from volatility.fmtspec import FormatSpec
from volatility.renderers import ColumnSortKey

__author__ = 'mike'

from volatility import renderers

class Address(int):
    """Integer class to allow renderers to differentiate between addresses and numbers"""
    def __new__(cls, number):
        return int.__new__(cls, number)

class Address64(int):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return int.__new__(cls, number)


class Hex(int):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return int.__new__(cls, number)
