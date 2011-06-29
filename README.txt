============================================================================
Volatility Framework - Volatile memory extraction utility framework
============================================================================

The Volatility Framework is a completely open collection of tools,
implemented in Python under the GNU General Public License, for the
extraction of digital artifacts from volatile memory (RAM) samples.
The extraction techniques are performed completely independent of the
system being investigated but offer visibilty into the runtime state
of the system. The framework is intended to introduce people to the
techniques and complexities associated with extracting digital artifacts
from volatile memory samples and provide a platform for further work into
this exciting area of research.

The Volatility distribution is available from: 
https://www.volatilesystems.com/default/volatility

Volatility should run on any platform that supports 
Python (http://www.python.org)

Volatility supports investigations of the following x86 bit memory images:

* Microsoft Windows XP Service Pack 2 and 3
* Microsoft Windows 2003 Server Service Pack 0, 1 and 2
* Microsoft Vista Service Pack 0, 1 and 2
* Microsoft 2008 Server Service Pack 1 and 2 (there is no SP 0)
* Microsoft Windows 7 Service Pack 0 and 1

Volatility does not provide memory sample acquisition
capabilities. For acquisition, there are both free and commercial
solutions available. If you would like suggestions about suitable 
acquisition solutions, please contact us at:

volatility (at) volatilesystems (dot) com

Volatility currently provides the following extraction capabilities for 
memory samples:

  - Image date and time
  - Running processes
  - Open network sockets
  - Open network connections
  - DLLs loaded for each process
  - Open files for each process
  - Open registry keys for each process
  - OS kernel modules
  - Mapping physical offsets to virtual addresses
  - Virtual Address Descriptor information
  - Addressable memory for each process
  - Memory maps for each process
  - Extract executable samples
  - Scanning examples: processes, threads, 
       sockets, connections, modules

Volatility also supports a variety of sample file formats and the
ability to convert between these formats:

  - Raw linear sample (dd)
  - Hibernation file
  - Crash dump file

Example Data
============

If you want to give Volatility a try, you can download exemplar
data hosted by NIST at the following url:

    http://www.cfreds.nist.gov/mem/memory-images.rar

Links to other public memory images can be found at the following url:

    http://code.google.com/p/volatility/wiki/FAQ

Mailing Lists
=============

Mailing lists to support the users and developers of Volatility
can be found at the following address:

    http://lists.volatilesystems.com/mailman/listinfo

Contact
=======
For information or requests, contact:

Volatile Systems

Web: http://www.volatilesystems.com/
     http://volatility.tumblr.com/
     
Email: volatility (at) volatilesystems (dot) com

IRC: #volatility on freenode

Requirements
============
- Python 2.6 or later, but not 3.0. http://www.python.org

Some plugins may have other requirements which can be found at: 
    http://code.google.com/p/volatility/wiki/FAQ

Quick Start
===========
1. Unpack the latest version of Volatility from
   https://www.volatilesystems.com/default/volatility

2. To see available options, run "python vol.py -h"  

   Example:

> python vol.py -h
Volatile Systems Volatility Framework 2.0
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/Users/user/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --info                Print information about all registered objects
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --cache-directory=/Users/user/.cache/volatility
                        Directory where cache files are stored
  --no-cache            Disable caching
  --tz=TZ               Sets the timezone for displaying timestamps
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address
  --output=text         Output in this format (format support is module
                        specific)
  --output-file=OUTPUT_FILE
                        write output in this file
  -v, --verbose         Verbose information
  -g KDBG, --kdbg=KDBG  Specify a specific KDBG virtual address
  --dtb=DTB             DTB Address
  --cache-dtb           Cache virtual to physical mappings
  --use-old-as          Use the legacy address spaces
  -w, --write           Enable write support
  --profile=WinXPSP2x86
                        Name of the profile to load
  -l LOCATION, --location=LOCATION
                        A URN location from which to load an address space

    Supported Plugin Commands:

        bioskbd         Reads the keyboard buffer from Real Mode memory
        connections     Print list of open connections [Windows XP Only]
        connscan2       Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
        crashinfo       Dump crash-dump information
        dlldump         Dump DLLs from a process address space
        dlllist         Print list of loaded dlls for each process
        driverscan      Scan for driver objects _DRIVER_OBJECT 
        files           Print list of open files for each process
        filescan        Scan Physical memory for _FILE_OBJECT pool allocations
        getsids         Print the SIDs owning each process
        hashdump        Dumps passwords hashes (LM/NTLM) from memory
        hibdump         Dumps the hibernation file to a raw file
        hibinfo         Dump hibernation file information
        hivedump        Prints out a hive
        hivelist        Print list of registry hives.
        hivescan        Scan Physical memory for _CMHIVE objects (registry hives)
        imagecopy       Copies a physical address space out as a raw DD image
        imageinfo       Identify information for the image 
        inspectcache    Inspect the contents of a cache 
        kdbgscan        Search for and dump potential KDBG values
        kpcrscan        Search for and dump potential KPCR values
        lsadump         Dump (decrypted) LSA secrets from the registry
        memdump         Dump the addressable memory for a process
        memmap          Print the memory map
        moddump         Dump a kernel driver to an executable file sample
        modscan2        Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects
        modules         Print list of loaded modules
        mutantscan      Scan for mutant objects _KMUTANT 
        netscan         Scan a Vista, 2008 or Windows 7 image for connections and sockets
        patcher         Patches memory based on page scans
        printkey        Print a registry key, and its subkeys and values
        procexedump     Dump a process to an executable file sample
        procmemdump     Dump a process to an executable memory sample
        pslist          print all running processes by following the EPROCESS lists 
        psscan          Scan Physical memory for _EPROCESS objects
        psscan2         Scan Physical memory for _EPROCESS pool allocations
        pstree          Print process list as a tree
        regobjkeys      Print list of open regkeys for each process
        sockets         Print list of open sockets
        sockscan        Scan Physical memory for _ADDRESS_OBJECT objects (tcp sockets)
        ssdt            Display SSDT entries
        strings         Match physical offsets to virtual addresses (may take a while, VERY verbose)
        testsuite       Run unit test suit using the Cache 
        thrdscan2       Scan physical memory for _ETHREAD objects
        vaddump         Dumps out the vad sections to a file
        vadinfo         Dump the VAD info
        vadtree         Walk the VAD tree and display in tree format
        vadwalk         Walk the VAD tree
        volshell        Shell in the memory image

3. To get more information on a sample and to make sure Volatility
   supports that sample type, run 'python vol.py imageinfo -f <imagename>'

   Example:
   
    > python vol.py -f win7.dmp imageinfo
    Volatile Systems Volatility Framework 2.0
    Determining profile based on KDBG search...
             Suggested Profile : Win7SP0x86
                     AS Layer1 : JKIA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/Users/M/Desktop/win7.dmp)
                      PAE type : No PAE
                           DTB : 0x185000
                          KDBG : 0x8296cbe8
                          KPCR : 0x8296dc00
             KUSER_SHARED_DATA : 0xffdf0000
           Image date and time : 2010-07-06 22:40:28 
     Image local date and time : 2010-07-06 22:40:28 
                    Image Type : 

4. Run some other tools. -f is a required option for all tools. Some
   also require/accept other options. Run "python vol.py <cmd> -h" for
   more information on a particular command.  A Command Reference wiki
   is also available on the Google Code site:

        http://code.google.com/p/volatility/wiki/CommandReference

   as well as Basic Usage:

        http://code.google.com/p/volatility/wiki/BasicUsage


Licensing and Copyright
=======================

Copyright (C) 2007-2011 Volatile Systems

Original Source:
Copyright (C) 2007 Komoku, Inc.
All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  
02111-1307, USA.


Bugs and Support
================
There is no support provided with Volatility. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. 

If you think you've found a bug, please report it at:

    http://code.google.com/p/volatility/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of volatility you're using
* The operating system used to run volatility
* The version of python used to run volatility
* The suspected operating system of the memory image
* The complete command line you used to run volatility

Depending on the operating system of the memory image, you may need to provide
additional information, such as:

For Windows:
* The suspected Service Pack of the memory image

For Linux:
* The suspected kernel version of the memory image

Other options for communicaton can be found at:
    http://code.google.com/p/volatility/wiki/FAQ

Missing or Truncated Information
================================
Volatile Systems makes no claims about the validity or correctness of the
output of Volatility. Many factors may contribute to the
incorrectness of output from Volatility including, but not
limited to, malicious modifications to the operating system,
incomplete information due to swapping, and information corruption on
image acquisition. 


Command Reference 
====================
The following url contains a reference of all commands supported by 
Volatility.

    http://code.google.com/p/volatility/wiki/CommandReference


