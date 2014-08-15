/*

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

*/

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "elf.h"
#include "getkcore.h"

static int debug = 0;

// how much data is read at once from /proc/kcore
static unsigned int chunk_size = 10000000;

void _debug_msg(const char *format,...)
{
    if (debug)
    {
        va_list va;
        va_start(va,format);
        vfprintf(stderr,format,va);
        va_end(va);
        printf("\n");
    }
}

void _die(const char* format,...) 
{
    va_list va;
    va_start(va,format);
    vfprintf(stderr,format,va);
    va_end(va);
    printf("\n");
    
    exit(1);
}

void _do_startup_checks(void)
{
    if (getuid() != 0)
        _die("This program must be run as root");

    if (access("/proc/kcore", F_OK) == -1)
        _die("/proc/kcore does not exist");  
}

void _write_lime_header(int out_fd, unsigned long long phys_off, unsigned long long size)
{
    lime_range l;

    l.magic   = 0x4C694D45;
    l.version = 1; 
    l.s_addr  = phys_off;
    l.e_addr  = phys_off + size - 1;
    memset(&l.reserved, 0x00, sizeof(l.reserved));

    _debug_msg("_write_lime_header: Made lime header for start: %llx end: %llx", l.s_addr, l.e_addr);

    if (write(out_fd, &l, sizeof(l)) != sizeof(l))
        _die("_write_lime_header: Error writing header for offset: %x", phys_off);
} 

void _read_write_region(int kcore_fd, int out_fd, Elf64_Phdr *p, unsigned long long phys_start, unsigned char *read_buf)
{
    unsigned long long wrote;
    unsigned long long left;
    unsigned long long to_read;
    unsigned long long rw_sz;

    // seek to the offset where the region is
    if (lseek64(kcore_fd, p->p_offset, 0) != (off_t)p->p_offset)
        _die("_read_write_region: Unable to seek to file offset %llx", p->p_offset); 

    wrote = 0;

    // read & write the region
    while (wrote < p->p_memsz)
    {
        memset(read_buf, 0x00, chunk_size);
        
        left = p->p_memsz - wrote;

        if (left < chunk_size)
            to_read = left;
        else
            to_read = chunk_size;

        rw_sz = read(kcore_fd, read_buf, to_read);

        if (rw_sz != to_read)
            _die("_read_write_region: Requested to read %llx bytes from %llx | %llx but received %llx", to_read, phys_start, phys_start + wrote, rw_sz); 

        rw_sz = write(out_fd, read_buf, to_read);

        if (rw_sz != to_read)
            _die("_read_write_region: Requested to write %llx bytes from %llx | %llx but wrote %llx", to_read, phys_start, phys_start + wrote, rw_sz); 

        wrote = wrote + to_read;
    }
    
    printf("Wrote %llu bytes from %llx\n", wrote, phys_start);

}

void _process_header(int kcore_fd, int out_fd, unsigned long long phdr_addr, unsigned long long phys_start, unsigned char *read_buf)
{
    Elf64_Phdr p;
 
    if (lseek64(kcore_fd, phdr_addr, 0) != (off_t)phdr_addr)
        _die("_process_header: Unable to seek to program header's offset: %x", phdr_addr);

    if (read(kcore_fd, &p, sizeof(p)) != sizeof(p))
        _die("_process_header: Unable to read program header: %x | %x\n", phdr_addr, phys_start);

    if (phys_start + 0xffff880000000000 == p.p_vaddr)
    {
        _write_lime_header(out_fd, phys_start, p.p_memsz);
        _read_write_region(kcore_fd, out_fd, &p, phys_start, read_buf);
    }       
}
 
void _write_region(int kcore_fd, int out_fd, unsigned long long phys_start, unsigned char *read_buf)
{
    Elf64_Ehdr h;
    unsigned short i;

    if (lseek64(kcore_fd, 0, 0) != 0)
        _die("_write_region: Unable to seek to offset 0");

    if (read(kcore_fd, &h, sizeof(h)) != sizeof(h))
        _die("_write_region: Unable to read ELF header for offset: %llx\n", phys_start);
 
    for (i = 0; i < h.e_phnum; i++)
        _process_header(kcore_fd, out_fd, h.e_phoff + (i * sizeof(Elf64_Phdr)), phys_start, read_buf);

}

char *_read_proc_iomem(void)
{
    int fd;
    off_t size;
    char *contents;

    fd = open("/proc/iomem", O_RDONLY);

    if (fd == -1)
        _die("_read_proc_iomem: Unable to open /proc/iomem");  

    size = 1000000;

    contents = malloc(size + 2);

    if (contents == NULL)
        _die("_read_proc_iomem: Unable to allocate buffer for reading /proc/iomem");

    *(contents + size + 1) = 0x00;

    if (read(fd, contents, size) < 1)
        _die("_read_proc_iomem: Unable to read /proc/iomem");

    close(fd);

    return contents;
}

// Parses /proc/iomem and calls _write_region with each found 
void _dump_ranges(int kcore_fd, int out_fd, unsigned char *read_buf)
{
    off_t size;
    off_t curoff;
    char *contents;
    char *cur;
    char *curn; 
    char *intbuf;
    char *dash;   
    unsigned long long start;
    unsigned long long end;

    contents = _read_proc_iomem();

    curoff = 0;

    size = strlen(contents);

    while (curoff < size)
    {
        // break up by newline
        cur = contents + curoff;
        curn = strstr(cur, "\n");

        if (curn == NULL)
            break;

        *curn = 0x00;

        // skip to next line if not RAM
        if (strstr(cur, "System RAM") == NULL)
        {
            curoff = curoff + curn - cur + 1; 
            continue;        
        }
        
        // 00100000-3fedffff : System RAM
        intbuf = strstr(cur, " ");
        dash = strstr(cur, "-");

        if (intbuf == NULL || dash == NULL || intbuf < dash)
            _die("parse_proc_iomem: Line broke parser: %s", cur);

        *dash   = 0x00;
        *intbuf = 0x00;

        start = strtoull(cur, NULL, 16);
        end   = strtoull(dash + 1, NULL, 16);

        _debug_msg("Found RAM at start: %llx end: %llx", start, end);

        _write_region(kcore_fd, out_fd, start, read_buf);
            
        curoff = curoff + curn - cur + 1; 
    }
}

int create_memory_dump(char *outfile)
{
    int kcore_fd;
    int out_fd;
    unsigned char *read_buf;

    read_buf = malloc(chunk_size);
    if (read_buf == NULL)
        _die("_create_memory_dump: Unable to allocate /proc/kcore read buffer");
 
    _do_startup_checks();

    kcore_fd = open("/proc/kcore", O_RDONLY);

    if (kcore_fd == -1)
        _die("create_memory_dump: Unable to open /proc/kcore for reading");

    out_fd = open(outfile, O_WRONLY|O_CREAT, 0700);

    _dump_ranges(kcore_fd, out_fd, read_buf);

    close(kcore_fd);
    close(out_fd);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        _die("Usage: ./getkcore <output file name>");  

    create_memory_dump(argv[1]);
    
    return 0;
}

