'''
Created on 6 Feb 2012

@author: mike
'''


class VolatilityException(Exception):
    """Generic Volatility Specific exception, to help differentiate from other exceptions"""
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class AddrSpaceError(VolatilityException):
    """Address Space Exception, so we can catch and deal with it in the main program"""
    def __init__(self):
        self.reasons = []
        VolatilityException.__init__(self, "No suitable address space mapping found")

    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = str(self) + "\nTried to open image as:\n"
        for k, v in self.reasons:
            result += " {0}: {1}\n".format(k, v)

        return result

class CacheRelativeURLException(VolatilityException):
    """Exception for gracefully not saving Relative URLs in the cache"""

