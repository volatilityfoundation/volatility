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
#  The source code in this file was inspired by the work of Matthieu Suiche,
#  http://sandman.msuiche.net/, and the information presented released as 
#  part of the Microsoft Interoperability Initiative:
#  http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-DRSR%5D.pdf
#  A special thanks to Matthieu for all his help!

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      bdolangavitt@wesleyan.edu
"""

#pylint: disable-msg=C0111

from struct import unpack
from struct import error as StructError

def recombine(outbuf):
    return "".join(outbuf[k] for k in sorted(outbuf.keys()))

def xpress_decode(inputBuffer):
    outputBuffer = {}
    outputIndex = 0
    inputIndex = 0
    indicatorBit = 0
    nibbleIndex = 0

    # we are decoding the entire input here, so I have changed
    # the check to see if we're at the end of the output buffer
    # with a check to see if we still have any input left.
    while inputIndex < len(inputBuffer):
        if (indicatorBit == 0):
            # in pseudocode this was indicatorBit = ..., but that makes no
            # sense, so I think this was intended...
            try:
                indicator = unpack("<L", inputBuffer[inputIndex:inputIndex + 4])[0]
            except StructError:
                return recombine(outputBuffer)

            inputIndex += 4
            indicatorBit = 32

        indicatorBit = indicatorBit - 1
        # check whether the bit specified by indicatorBit is set or not 
        # set in indicator. For example, if indicatorBit has value 4 
        # check whether the 4th bit of the value in indicator is set
        if not (indicator & (1 << indicatorBit)):
            try:
                outputBuffer[outputIndex] = inputBuffer[inputIndex]
            except IndexError:
                return recombine(outputBuffer)

            inputIndex += 1
            outputIndex += 1
        else:
            # Get the length. This appears to use a scheme whereby if
            # the value at the current width is all ones, then we assume
            # that it is actually wider. First we try 3 bits, then 3
            # bits plus a nibble, then a byte, and finally two bytes (an
            # unsigned short). Also, if we are using a nibble, then every
            # other time we get the nibble from the high part of the previous 
            # byte used as a length nibble.
            # Thus if a nibble byte is F2, we would first use the low part (2),
            # and then at some later point get the nibble from the high part (F).

            try:
                length = unpack("<H", inputBuffer[inputIndex:inputIndex + 2])[0]
            except StructError:
                return recombine(outputBuffer)

            inputIndex += 2
            offset = length / 8
            length = length % 8
            if length == 7:
                if nibbleIndex == 0:
                    nibbleIndex = inputIndex
                    length = ord(inputBuffer[inputIndex]) % 16
                    inputIndex += 1
                else:
                    # get the high nibble of the last place a nibble sized
                    # length was used thus we don't waste that extra half
                    # byte :p
                    length = ord(inputBuffer[nibbleIndex]) / 16
                    nibbleIndex = 0

                if length == 15:
                    length = ord(inputBuffer[inputIndex])
                    inputIndex += 1
                    if length == 255:
                        try:
                            length = unpack("<H", inputBuffer[inputIndex:inputIndex + 2])[0]
                        except StructError:
                            return recombine(outputBuffer)
                        inputIndex = inputIndex + 2
                        length = length - (15 + 7)
                    length = length + 15
                length = length + 7
            length = length + 3

            while length != 0:
                try:
                    outputBuffer[outputIndex] = outputBuffer[outputIndex - offset - 1]
                except KeyError:
                    return recombine(outputBuffer)
                outputIndex += 1
                length -= 1

    return recombine(outputBuffer)

try:
    import pyxpress #pylint: disable-msg=F0401

    xpress_decode = pyxpress.decode
except ImportError:
    pass

if __name__ == "__main__":
    import sys
    dec_data = xpress_decode(open(sys.argv[1]).read())
    sys.stdout.write(dec_data)
