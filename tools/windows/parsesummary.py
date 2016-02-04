import json
import sys
import os

"""
Author: Gleeda <jamie.levy@gmail.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version
2 of the License, or (at your option) any later version.

parsesummary.py [summary_file]
    Parses summary files created from the dumpfiles plugin

"""

def usage(name):
    print "{0} [summary_file]".format(name)

def main():
    try:
        summary = sys.argv[1]
        if os.path.isfile(summary):
            f = open(summary, "r")
        else:
            print summary, "is not a file!"
            usage(sys.argv[0])
            return
    except:
        usage(sys.argv[0])
        return

    heading = "*" * 80
    for line in f.readlines():
        print heading
        item = json.loads(line.strip())
        print "File: {0} -> {1}".format(item["name"], item["ofpath"])
        print "\tPID: {0}".format(item["pid"])
        print "\t_FILE_OBJECT offset: 0x{0:x}".format(item["fobj"])
        print "\tType: {0}".format(item["type"])
        vacbary = item.get("vacbary", [])
        if item["type"] == "SharedCacheMap" and vacbary != []:
            for vacb in vacbary:
                print "\tSize: {0}".format(vacb["size"])
                present = vacb.get("present", None)
                padding = vacb.get("pad", None)
                if present != None:
                    print "\tPresent Pages:" 
                    for page in present:
                        print "\t\tOffset(V): 0x{0:x}, Length: {1}".format(page[0], page[1])
            
        else:
            present = item.get("present", None)
            if present != None:
                print "\tPresent Pages:"
                if item["type"] != "SharedCacheMap":
                    for page in present:
                        print "\t\tOffset(P) 0x{0:x} FileOffset: 0x{1:x}, Size: {2}".format(page[0], page[1], page[2])
            padding = item.get("pad", None)
        if padding != None:
            print "\tPadding:"
            for pad in padding:
                print "\t\tFileOffset: 0x{0:x} x 0x{1:x}".format(pad[0], pad[1])
    print heading

if __name__ == "__main__":
    main()
