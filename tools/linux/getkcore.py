"""
Author: Andrew Case / andrew@dfir.org
License: GPLv2

TOOLS PURPOSE:
64-bit Linux Physical Memory Acquistion from Userland

NOT FOR PUBLIC RELEASE:
This file is not to be distributed publicly until the release of the Art of Memory Forensics is published
A cleaned up version of it will be released with the book's materials

ACQUISTION ALGORITHM:
This script relies on the static virtual mapping of all RAM kept by x64 Linux systems.
This mapping is illustrated here: http://lxr.free-electrons.com/source/Documentation/x86/x86_64/mm.txt

To reach these mappings we use the /proc/kcore file.
This file exposes all of physical memory (including hardware devices) as ELF sections of a core dump file.

To acquire memory, the script first parses /proc/iomem and determines ranges of "System RAM".
It then parses the sections of /proc/kcore and matches "System RAM" regions to those found in the kcore file.
This matching is possible by using the static offset (0xffff880000000000) of the virtual mapping of RAM.
See the _find_kcore_sections function for this algorithm

Each RAM region found is then written to a LiME formatted file so that it can be immediately analyzed with Volatility.

"""

import os, sys, struct

try:
    import elftools
except:
    print "pyelftools not found. Please install"
    exit(1)

from elftools.elf.elffile import ELFFile

##### CHANGE THIS TO MAKE DEBUG MESSAGES PRINT DURING ACQUISTION #####
debug = 1

def _print_msg(msg):
    print msg

def _debug_msg(msg):
    if debug:
        _print_msg(msg)

def _die(msg):
    _print_msg(msg + " Exiting.")
    exit(1)

def _do_startup_checks():
    if sys.platform.find("linux") == -1:
        die("This script only acquires memory from Linux systems.")

    if os.getuid() != 0:
        die("This script must be run as root.")

    if not os.path.exists("/proc/kcore"):
        die("/proc/kcore not enabled on this system.") 

def _parse_proc_iomem():
    ranges = {}

    ram_regions = [x for x in open("/proc/iomem", "r").readlines() if x.find("System RAM") != -1]

    # 00010000-0009efff : System RAM\n
    for region in ram_regions:
        # gets the addresses
        first = region.split()[0]

        ents = first.split("-")

        (start, end) = (int(ents[0], 16), int(ents[1], 16))

        _debug_msg("_parse_proc_iomem: Adding range %#x-%#x" % (start, end))

        ranges[start + 0xffff880000000000] = (start, end)

    return ranges

def  _find_kcore_sections(ram_ranges):
    sections = []

    with open("/proc/kcore", 'rb') as f:
        elffile = ELFFile(f)

        for section in elffile.iter_segments(): 
            file_off = section['p_offset']
            vaddr    = section['p_vaddr']
            sz       = section['p_memsz']

            if not vaddr in ram_ranges:
                continue

            # the start address in physical memory of the system from /proc/iomem
            phys_off = ram_ranges[vaddr][0]

            _debug_msg("Found RAM region: %.08x %.08x %.08x" % (file_off, vaddr, sz))

            sections.append((file_off, phys_off, sz)) 
    
    return sections

def _make_lime_header(phys_off, sz):
    magic   = struct.pack("<I", 0x4C694D45)
    version = struct.pack("<I", 1)
    start   = struct.pack("<Q", phys_off)
    end     = struct.pack("<Q", phys_off + sz - 1)
    reserved = "\x00" * 8

    _debug_msg("Created lime header: %.16x %.16x" % (phys_off, phys_off + sz - 1))

    return magic + version + start + end + reserved     

def _write_file(outfd, data, size_of_data):    
    wrote = os.write(outfd, data)

    if wrote != size_of_data:
        _die("_write_file: Asked to write %d bytes but %d written!" % (size_of_data, wrote))

def _write_section_data(outfd, file_off, sz):
    chunk_size = 10000000

    kcore_fd = os.open("/proc/kcore", os.O_RDONLY)
    os.lseek(kcore_fd, file_off, os.SEEK_SET)

    wrote = 0

    while wrote < sz:
        left = sz - wrote

        if left < chunk_size:
            to_read = left
        else:   
            to_read = chunk_size

        buf = os.read(kcore_fd, to_read)
        
        buf_wrote = os.write(outfd, buf)

        if buf_wrote != to_read:
            _die("_write_section_data: Attempt to read from %d bytes from %x read %d bytes" % (to_read, file_off + wrote, to_read))

        wrote = wrote + to_read

    if wrote != sz:
        _die("_write_section_data: Should have acquired %d bytes from section %x but instead acquired %d" % (sz, file_off, wrote))

    os.close(kcore_fd)

def _write_memory_dump(outfd, kcore_sections):
    for (file_off, phys_off, sz) in kcore_sections:
        lime_header = _make_lime_header(phys_off, sz)

        _write_file(outfd, lime_header, len(lime_header))

        _write_section_data(outfd, file_off, sz)

# entry point to acquistion process
def create_memory_dump(output_file):
    _do_startup_checks()

    _debug_msg("Enumerating ranges from /proc/iomem")
    ram_ranges = _parse_proc_iomem()

    _debug_msg("Enumerating sections from /proc/kcore")
    kcore_sections = _find_kcore_sections(ram_ranges)
    
    outfd = os.open(output_file, os.O_WRONLY|os.O_CREAT, 770)

    _debug_msg("Writing sections to LiME formatted file")
    _write_memory_dump(outfd, kcore_sections)

    os.close(outfd)

def main(): 
    if len(sys.argv) < 2:
        die("Usage: %s <output file name>" % (sys.argv[0]))
    
    outfile = sys.argv[1]

    create_memory_dump(outfile)


if __name__ == "__main__":
    main()










