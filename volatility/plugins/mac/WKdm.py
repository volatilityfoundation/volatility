# 
# Python port of WKdm compression  / decompression by 
# Golden G. Richard III (@nolaforensix, golden@arcanealloy.com)
# December 2013
#
# For compression and decompression of 4K pages.
#
# Based loosely on WKdm.c, by:
# 
# *  Paul Wilson -- wilson@cs.utexas.edu
# *  Scott F. Kaplan -- sfkaplan@cs.utexas.edu
# *  September 1997
#
# but designed specifically to be compatible with the optimized x86_64
# assembler version in xnu-2422.1.72/osfmk/x86_64/WKdmCompress_new*
# (Mac OS X Mavericks 10.9 kernel source).  Apples's assembler version
# eliminates the unused "version word" in the header, reducing header
# size to 3 words, making this version incompatible with the original
# WKdm.c (for what it's worth).  The Apple version also introduces a
# compression budget for WKdm_compress, which results in a compression
# failure if the budget (expressed in bytes) is exceeded.  The
# compression budget is also supported by this version for
# compatibility.
#

import math

class WKdm:
    
    ##################################################################
    ##################################################################
    # DO NOT CHANGE THESE: Correct operation depends on 4K page size
    # and there are various other non-trivial dependencies
    ##################################################################
    ##################################################################
    WORD_SIZE_IN_BYTES        = 4
    PAGE_SIZE_IN_WORDS	      = 1024
    PAGE_SIZE_IN_BYTES	      = 4096
    DICTIONARY_SIZE_IN_WORDS  = 16
    HEADER_SIZE_IN_WORDS      = 3                      
    TAGS_AREA_OFFSET_IN_WORDS = HEADER_SIZE_IN_WORDS
    TAGS_AREA_SIZE_IN_WORDS   = 64
    NUM_LOW_BITS	      = 10
    LOW_BITS_MASK	      = 0x3FF
    ALL_ONES_MASK	      = 0xFFFFFFFF
    TWO_BITS_PACKING_MASK     = 0x03030303
    FOUR_BITS_PACKING_MASK    = 0x0F0F0F0F
    TEN_LOW_BITS_MASK	      = 0x000003FF
    TWENTY_TWO_HIGH_BITS_MASK = 0xFFFFFC00
    ZERO_TAG	              = 0x0
    PARTIAL_TAG	              = 0x1
    MISS_TAG	              = 0x2
    EXACT_TAG	              = 0x3
    SINGLE_BYTE_MASKS = [0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000]
    ##################################################################
    ##################################################################

    ##################################################################
    # These are the constants for the hash function lookup table.
    # Only zero maps to zero.  The rest of the table is the result of
    # appending 17 randomizations of the multiples of 4 from 4 to 56.
    ##################################################################
    HASH_LOOKUP_TABLE_CONTENTS = [ 
        0, 52,  8, 56, 16, 12, 28, 20,  4, 36, 48, 24, 44, 40, 32, 60, 
        8, 12, 28, 20,  4, 60, 16, 36, 24, 48, 44, 32, 52, 56, 40, 12, 
        8, 48, 16, 52, 60, 28, 56, 32, 20, 24, 36, 40, 44,  4,  8, 40, 
        60, 32, 20, 44,  4, 36, 52, 24, 16, 56, 48, 12, 28, 16,  8, 40, 
        36, 28, 32, 12,  4, 44, 52, 20, 24, 48, 60, 56, 40, 48,  8, 32, 
        28, 36,  4, 44, 20, 56, 60, 24, 52, 16, 12, 12,  4, 48, 20,  8, 
        52, 16, 60, 24, 36, 44, 28, 56, 40, 32, 36, 20, 24, 60, 40, 44, 
        52, 16, 32,  4, 48,  8, 28, 56, 12, 28, 32, 40, 52, 36, 16, 20, 
        48,  8,  4, 60, 24, 56, 44, 12,  8, 36, 24, 28, 16, 60, 20, 56, 
        32, 40, 48, 12,  4, 44, 52, 44, 40, 12, 56,  8, 36, 24, 60, 28, 
        48,  4, 32, 20, 16, 52, 60, 12, 24, 36,  8,  4, 16, 56, 48, 44, 
        40, 52, 32, 20, 28, 32, 12, 36, 28, 24, 56, 40, 16, 52, 44,  4, 
        20, 60,  8, 48, 48, 52, 12, 20, 32, 44, 36, 28,  4, 40, 24,  8, 
        56, 60, 16, 36, 32,  8, 40,  4, 52, 24, 44, 20, 12, 28, 48, 56, 
        16, 60,  4, 52, 60, 48, 20, 16, 56, 44, 24,  8, 40, 12, 32, 28, 
        36, 24, 32, 12,  4, 20, 16, 60, 36, 28,  8, 52, 40, 48, 44, 56  
    ]


    ##################################################################
    # WK_pack_2bits(): Pack some multiple of four words holding
    # two-bit tags (in the low two bits of each byte) into an integral
    # number of words, i.e., one fourth as many. Data in the
    # source_buf is used starting at index 0 up to and not including
    # index source_end. The packed data is written into the dest_buf
    # starting at index dest_start.  NOTE: Pad the input with zeroes
    # to a multiple of four words, or else.
    ##################################################################
    def WK_pack_2bits(self, 
                      source_buf,
                      source_end,
                      dest_buf,
                      dest_start):

        j = dest_start
        k = source_end

        src_next = 0
        
        # loop to repeatedly grab four input words and pack it into 1
        # output word.
        while src_next < source_end:
            temp = source_buf[src_next]
            temp |= (source_buf[src_next+1] << 2)
            temp |= (source_buf[src_next+2] << 4)
            temp |= (source_buf[src_next+3] << 6)
            dest_buf[dest_start] = temp

            dest_start += 1     
            src_next += 4

        return dest_start

        
    ###################################################################
    # WK_pack_4bits(): Pack an even number of words holding 4-bit
    # patterns in the low bits of each byte into half as many
    # words. Data in the source_buf is used starting at index 0 up
    # to and not including index source_end. The packed data is
    # written into the dest_buf starting at index dest_start.
    # NOTE: Pad the input with zeroes to an even number of words,
    # or else.
    ################################################################## 
    def WK_pack_4bits(self, 
                      source_buf,
                      source_end,
                      dest_buf, 
                      dest_start):
        src_next = 0
  
        # loop to repeatedly grab two input words and pack it into 1
        # output word.
        while src_next < source_end:
            temp = source_buf[src_next]
            temp |= (source_buf[src_next+1] << 4)
            dest_buf[dest_start] = temp
            
            dest_start += 1     
            src_next += 2

        return dest_start

    
    ###################################################################
    # WK_pack_3_tenbits(): Pack a sequence of three ten bit items
    # into one word. Data in the source_buf is used starting at
    # index 0 up to and not including source_end. The packed data
    # is written into the dest_buf starting at index dest_start.
    # NOTE: Pad out the input with zeroes to an even number of
    # words, or else.
    ################################################################### 
    def WK_pack_3_tenbits(self,
                          source_buf,
                          source_end,
                          dest_buf,
                          dest_start):
        
        src_next = 0
            
        # loop to repeatedly grab three input words and pack it into 1
        # output word.
        while src_next < source_end:
            temp = source_buf[src_next]
            temp |= (source_buf[src_next+1] << 10)
            temp |= (source_buf[src_next+2] << 20)
            dest_buf[dest_start] = temp
            
            dest_start += 1     
            src_next += 3
            
        return dest_start

    
     ################################################################### 
     # WK_unpack_2bits(): Take any number of words containing 16
     # two-bit values and unpack them into four times as many words
     # containg those two bit values as bytes (with the low two
     # bits of each byte holding the actual value).  Data is read
     # from input_buf starting at index input_start and up to but
     # not including input_end.  Unpacked data is placed in
     # output_buf.
     ################################################################### 
    def WK_unpack_2bits(self,
                        input_buf,
                        input_start,
                        input_end,
                        output_buf):
        
        output_next = 0
            
        # loop to repeatedly grab one input word and unpack it into
        # 4 output words.
        while input_start < input_end:
            temp = input_buf[input_start]
            output_buf[output_next]   = temp        & self.TWO_BITS_PACKING_MASK
            output_buf[output_next+1] = (temp >> 2) & self.TWO_BITS_PACKING_MASK
            output_buf[output_next+2] = (temp >> 4) & self.TWO_BITS_PACKING_MASK
            output_buf[output_next+3] = (temp >> 6) & self.TWO_BITS_PACKING_MASK
            
            output_next += 4
            input_start += 1
            
        return output_next


    ################################################################### 
    # WK_unpack_4bits(): Unpack four bits consumes any number of
    # words holding 8 4-bit values per word, and unpacks them into
    # twice as many words, with each value in a separate byte.
    # (The four-bit values occupy the low halves of the bytes in
    # the result). Data is read from input_buf starting at index
    # input_start and up to but not including input_end.  Unpacked
    # data is placed in output_buf.
    ################################################################### 
    def WK_unpack_4bits(self,
                        input_buf,
                        input_start,
                        input_end,
                        output_buf):

        output_next = 0

        # loop to repeatedly grab one input word and unpack it into 2
        # output words.
        while input_start < input_end:
            temp = input_buf[input_start]
            output_buf[output_next] = temp & self.FOUR_BITS_PACKING_MASK
            output_buf[output_next+1] = (temp >> 4) & self.FOUR_BITS_PACKING_MASK        

            output_next += 2
            input_start += 1

        return output_next

        
    ################################################################### 
    # WK_unpack_3_tenbits(): Unpack three 10-bit items from the
    # low 30 bits of any number of 32-bit words. Data is read from
    # input_buf starting at index input_start and up to but not
    # including input_end.  Unpacked data is placed in output_buf.
    ################################################################### 
    def WK_unpack_3_tenbits(self,
                            input_buf,
                            input_start,
                            input_end,
                            output_buf):

        output_next = 0

        # loop to fetch 1 word of input, splitting each into three words of
        # output with 10 meaningful low order bits.
        while input_start < input_end:
            temp = input_buf[input_start]
            output_buf[output_next] = temp & self.LOW_BITS_MASK
            output_buf[output_next+1] = (temp >> 10) & self.LOW_BITS_MASK
            output_buf[output_next+2] = temp >> 20

            input_start += 1
            output_next += 3

        return output_next


    ################################################################### 
    # WKdm_compress(): Compress a src_buf containing num_input_words
    # 32-bit words into a dest_buf of 32-bit words.  Returns size of
    # dest_buf or -1 if the compression budget (expressed in bytes) is
    # exceeeded, which also results in undefined contents in dest_buf.
    ################################################################### 
    def WKdm_compress(self, 
                      src_buf,
                      dest_buf,
                      num_input_words,
                      compression_budget):

        dictionary=[0] * self.DICTIONARY_SIZE_IN_WORDS
        hashLookupTable = self.HASH_LOOKUP_TABLE_CONTENTS

        # update compression budget based on fixed overhead
        compression_budget -= (self.HEADER_SIZE_IN_WORDS + 
                               self.TAGS_AREA_SIZE_IN_WORDS) * self.WORD_SIZE_IN_BYTES

        # arrays that hold output data in intermediate form during modeling 
        # and whose contents are packed into the actual output after modeling 

        tempTagsArray = [0] * 300                # tags for everything          
        tempQPosArray = [0] * 300                # queue positions for matches  
        tempLowBitsArray = [0] * 1200            # low bits for partial matches 

        # boundary_tmp will be used for keeping track of what's where in
        # the compressed page during packing

        boundary_tmp=0

        next_full_patt = 0                   # index into dest_buf
        next_tag = 0                         # index into tempTagsArray 
        next_qp = 0                          # index into tempQPosArray
        next_low_bits = 0                    # index into tempLowBitsArray
        next_input_word = 0                  # index into src_buf

        # initialize dictionary
        for i in range(0,15):
            dictionary[i] = 1

        # process all input words
        next_full_patt = self.TAGS_AREA_OFFSET_IN_WORDS + self.TAGS_AREA_SIZE_IN_WORDS 
        while next_input_word < num_input_words:
            input_word = src_buf[next_input_word]
            dict_location = hashLookupTable[(input_word >> 10) & 0xFF] / 4
            dict_word = dictionary[dict_location]

            if input_word == dict_word:
                tempTagsArray[next_tag / 4] |= (self.EXACT_TAG << (((next_tag) % 4) * 8))
                next_tag += 1
                tempQPosArray[next_qp / 4] |= (dict_location << (((next_qp) % 4) * 8))
                next_qp += 1
            elif input_word == 0:
                tempTagsArray[next_tag / 4] |= (self.ZERO_TAG << (((next_tag) % 4) * 8))
                next_tag += 1
            else:
                input_high_bits = input_word >> self.NUM_LOW_BITS
                dict_word_high_bits = dict_word >> self.NUM_LOW_BITS
                if input_high_bits == dict_word_high_bits:
                    tempTagsArray[next_tag / 4] |= (self.PARTIAL_TAG << (((next_tag) % 4) * 8))
                    next_tag += 1
                    tempQPosArray[next_qp / 4] |= (dict_location << (((next_qp) % 4) * 8))
                    next_qp += 1
                    tempLowBitsArray[next_low_bits] = input_word & self.LOW_BITS_MASK
                    next_low_bits += 1
                    dictionary[dict_location] = input_word
                else:
                    # check compression budget and fail immediately if exhausted
                    compression_budget -= self.WORD_SIZE_IN_BYTES
                    if compression_budget < 0:
                        return -1

                    tempTagsArray[next_tag / 4] |= (self.MISS_TAG << (((next_tag) % 4) * 8))
                    next_tag += 1
                    dest_buf[next_full_patt] = input_word
                    next_full_patt += 1
                    dictionary[dict_location] = input_word

            next_input_word += 1

        dest_buf[0] = next_full_patt            # qpos area start

        # Pack the tags into the tags area, between the page header
        # and the full words area.  No padding because page size is
        # assumed to be a multiple of 16.  Compression budget associated
        # with this area has already been deducted.

        boundary_tmp = self.WK_pack_2bits(tempTagsArray,
                                          next_tag / 4,                                         
                                          dest_buf,
                                          self.TAGS_AREA_OFFSET_IN_WORDS)

        # Pack the queue positions into the area just after the full
        # words.  Round up the size of the region to a multiple of two
        # words.

        endQPosArray = int(math.ceil(next_qp / 8.0)) * 2
        next_qp = int(math.ceil(next_qp / 4.0))

        # Pad the array with zeros to avoid corrupting real packed
        # values. 
        
        while (next_qp < endQPosArray):
            tempQPosArray[next_qp] = 0
            next_qp += 1


        # check compression budget and fail immediately if exhausted
        compression_budget -= (endQPosArray / 2) * self.WORD_SIZE_IN_BYTES
        if compression_budget < 0:
            return -1

        boundary_tmp = self.WK_pack_4bits(tempQPosArray,
                                          endQPosArray,
                                          dest_buf,
                                          next_full_patt)
        
        # Record (in the header) where packing queue positions stopped,
        # which is where packing of low bits will start.

        dest_buf[1] = boundary_tmp

        # Pack the low bit patterns into the area just after the queue
        # positions.  Round up the size of the region region to a
        # multiple of three words.

        endLowBitsArray = int(math.ceil(next_low_bits / 3.0)) * 3

        # Pad the array with zeros to avoid corrupting real packed
        # values. 

        while (next_low_bits < endLowBitsArray):
            tempLowBitsArray[next_low_bits] = 0
            next_low_bits += 1
            
        # check compression budget and fail immediately if exhausted
        compression_budget -= (endLowBitsArray / 3) * self.WORD_SIZE_IN_BYTES
        if compression_budget < 0:
            return -1

        boundary_tmp = self.WK_pack_3_tenbits (tempLowBitsArray,
                                               endLowBitsArray,
                                               dest_buf,
                                               boundary_tmp)

        dest_buf[2] = boundary_tmp

        return boundary_tmp


    ################################################################### 
    # WKdm_decompress(): Decompress a src_buf containing 32-bit words
    # into a dest_buf of 32-bit words.  Returns size of decompressed
    # buffer or -1 on decompression error (in which case the
    # dest_buf contents are undefined).
    ###################################################################  
    def WKdm_decompress (self,
                         src_buf,
                         dest_buf):

        dictionary = [0] * self.DICTIONARY_SIZE_IN_WORDS
        hashLookupTable = self.HASH_LOOKUP_TABLE_CONTENTS

        # arrays that hold output data in intermediate form during modeling 
        # and whose contents are packed into the actual output after modeling 

        tempTagsArray = [0] * 300        # tags for everything          
        tempQPosArray = [0] * 300        # queue positions for matches  
        tempLowBitsArray = [0] * 1200    # low bits for partial matches 

        # initialize dictionary

        for i in range(0,15):
            dictionary[i] = 1

        try:
            self.WK_unpack_2bits(src_buf,
                                 self.TAGS_AREA_OFFSET_IN_WORDS,
                                 self.TAGS_AREA_OFFSET_IN_WORDS + self.TAGS_AREA_SIZE_IN_WORDS,
                                 tempTagsArray)

            self.WK_unpack_4bits(src_buf,
                                 src_buf[0], 
                                 src_buf[1],
                                 tempQPosArray)

            self.WK_unpack_3_tenbits(src_buf,
                                     src_buf[1],
                                     src_buf[2], 
                                     tempLowBitsArray)

            next_tag = 0                                                                     # index into tempTagsArray
            tags_area_end = self.PAGE_SIZE_IN_WORDS 
            next_qp = 0                                                                      # index into tempQPosArray
            next_low_bits = 0                                                                # index into tempLowBitsArray
            next_full_word = self.TAGS_AREA_OFFSET_IN_WORDS + self.TAGS_AREA_SIZE_IN_WORDS   # index into src_buf
            next_output = 0                                                                  # index into dest_buf

            while (next_tag < tags_area_end):
                tag = (tempTagsArray[next_tag / 4] & self.SINGLE_BYTE_MASKS[next_tag % 4]) >> (((next_tag) % 4) * 8)

                if tag == self.ZERO_TAG:
                    dest_buf[next_output] = 0
                elif tag == self.EXACT_TAG:
                    dict_location = (tempQPosArray[next_qp / 4] & self.SINGLE_BYTE_MASKS[next_qp % 4]) >> (((next_qp) % 4) * 8)
                    next_qp += 1
                    dest_buf[next_output] = dictionary[dict_location]
                elif tag == self.PARTIAL_TAG:
                    dict_location = (tempQPosArray[next_qp / 4] & self.SINGLE_BYTE_MASKS[next_qp % 4]) >> (((next_qp) % 4) * 8)
                    temp = dictionary[dict_location]
                    # strip out low bits 
                    temp = ((temp >> self.NUM_LOW_BITS) << self.NUM_LOW_BITS)
                    # add in stored low bits from temp array 
                    temp = temp | tempLowBitsArray[next_low_bits]
                    next_low_bits += 1
                    # replace old value in dict
                    dictionary[dict_location] = temp   
                    dest_buf[next_output] = temp                     # and echo it to output 
                    next_qp += 1
                elif tag == self.MISS_TAG:
                    missed_word = src_buf[next_full_word]
                    next_full_word += 1
                    dict_location = hashLookupTable[(missed_word >> 10) & 0xFF] / 4
                    dictionary[dict_location] = missed_word
                    dest_buf[next_output] = missed_word
                else:
                    return -1 # fail, buffer is corrupted
                    #print "BAD TAG!!"

                next_tag += 1
                next_output += 1

            return next_output
        except:
            return -1

    
###########################################################
###########################################################
# testing area
###########################################################
###########################################################

#from struct import *

import sys
import time


def main():

    
    NUMBER_OF_ITERATIONS=1000
    w = WKdm()

#     src_buf_asm = [0]  * (w.PAGE_SIZE_IN_WORDS+100)
#     dest_buf_asm = [0] * (w.PAGE_SIZE_IN_WORDS+100)

    
    src_buf = [0]  * (w.PAGE_SIZE_IN_WORDS+100)
    dest_buf = [0] * (w.PAGE_SIZE_IN_WORDS+100)
    t=0


    for i in range(w.PAGE_SIZE_IN_WORDS):
        src_buf[i] = i * i + i
        if i % 10 == 0:
            src_buf[i] = 0
        elif i % 11 == 0:
            src_buf[i]=0xFFFFFFFF

    before = time.time()
    for i in range(NUMBER_OF_ITERATIONS):
        t += w.WKdm_compress(src_buf, dest_buf, w.PAGE_SIZE_IN_WORDS, 4096)
        t += w.WKdm_decompress(dest_buf, src_buf)
    total = time.time() - before
    
    print "Python timing: " + str(NUMBER_OF_ITERATIONS / total) + " compression / decompression pairs per second."


if __name__ == "__main__":
    main()













