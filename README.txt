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

Volatility supports investigations of Microsoft Windows XP Service 
Pack 2 memory images. 

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

In particular, you may want to check out the following sample: 

xp-laptop-2005-07-04-1430.img

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
- Python 2.5 or later. http://www.python.org

Quick Start
===========
1. Unpack the latest version of Volatility from
   https://www.volatilesystems.com/default/volatility

2. To see available options, run "python volatility"

   Example:

  > python volatility
	Volatile Systems Volatility Framework v1.3
	Copyright (C) 2007,2008 Volatile Systems
	Copyright (C) 2007 Komoku, Inc.
	This is free software; see the source for copying conditions.
	There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

	usage: volatility cmd [cmd_opts]

	Run command cmd with options cmd_opts
	For help on a specific command, run 'volatility cmd --help'

	Supported Internel Commands:
		connections    	Print list of open connections
		connscan       	Scan for connection objects
		connscan2      	Scan for connection objects
		datetime       	Get date/time information for image
		dlllist        	Print list of loaded dlls for each process
		dmp2raw        	Convert a crash dump to a raw dump
		dmpchk         	Dump crash dump information
		files          	Print list of open files for each process 
		hibinfo        	Convert hibernation file to linear sample
		ident          	Identify image properties 
		memdmp         	Dump the addressable memory for a process
		memmap         	Print the memory map
		modscan        	Scan for modules
		modscan2       	Scan for module objects
		modules        	Print list of loaded modules
		procdump       	Dump a process to an executable sample
		pslist         	Print list of running processes
		psscan         	Scan for EPROCESS objects
		psscan2        	Scan for process objects
		raw2dmp        	Convert a raw dump to a crash dump
		regobjkeys     	Print list of open regkeys for each process
		sockets        	Print list of open sockets
		sockscan       	Scan for socket objects
		sockscan2      	Scan for socket objects
		strings        	Match physical offsets to virtual addresses
		thrdscan       	Scan for ETHREAD objects
		thrdscan2      	Scan for thread objects
		vaddump        	Dump the Vad sections to files
		vadinfo        	Dump the VAD info
		vadwalk        	Walk the vad tree

	Supported Plugin Commands:
		memmap_ex_2    	Example: Print the memory map
		pslist_ex_1    	Example: Print list running processes
		pslist_ex_3    	Example: Print list running processes
		usrdmp_ex_2    	Example: Dump the address space for a process

	Example: volatility pslist -f /path/to/my/file

3. To get more information on a sample and to make sure Volatility
   supports that sample type, run 'python volatility ident -f <imagename>'

   Example:
   
  > python volatility ident -f c:\images\image1.dump
              Image Name: c:\images\image1.dump
              Image Type: XP SP2
                 VM Type: nopae
                     DTB: 0x39000
                Datetime: Mon Feb 19 20:52:08 2007

4. Run some other tools. -f is a required option for all tools. Some
   also require/accept other options. Run "volatility <cmd> --help" for
   more information on a particular command.


Licensing and Copyright
=======================

Copyright (C) 2007,2008 Volatile Systems

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
PURPOSE. Bugs may be reported to volatility (at) volatilesystems (dot) com. 
However, Volatile Systems makes no guarantees of any corrective
action or reply, written or verbal.

Missing or Truncated Information
================================
Volatile Systems makes no claims about the validity or correctness of the
output of Volatility. Many factors may contribute to the
incorrectness of output from Volatility including, but not
limited to, malicious modifications to the operating system,
incomplete information due to swapping, and information corruption on
image acquisition. 


Command Descriptions
====================
The following is a short description of some commands supported by
Volatility.

connections
-----------
Lists all open connections that were active at the time of the memory
sample's acquisition. If -t and -b are not specified, Volatility
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)

connscan
--------
Scans the flat physical address space for connection objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)

datetime
--------
Print the system date and time recognized by the Windows kernel at the
time the image was acquired. If -t and -b are not specified, Volatility
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)

dlllist
-------
For each process running in the system, identify the base virtual
address, size, and filesystem path to all DLLs loaded in that
process. If -t and -b are not specified, Volatility
will attempt to infer reasonable values. 

NOTE: dlllist output may be very verbose. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of EPROCESS object
     -p   <pid>     Pid of process

dmp2raw
-------
Convert sample stored in Crash Dump format to a raw linear sample,
similar to that produced by dd.

  Options:
     -f   <Image>   Crash dump file to load
     -o   <outfile>  Raw output file

dmpchk
-------
Extract meta information stored in Crash Dump file.

  Options:
     -f   <Image>   Crash dump file to load

files
-----
For each process running in the system, identify all open file handles
and the absolute filesystem path to that file. If -t and -b are not
specified, Volatility will attempt to infer reasonable values.

NOTE: files output may be very verbose. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of EPROCESS object
     -p   <pid>     Pid of process

hibinfo
-------
Extract meta information stored in a hibernation file and convert
sample to a raw linear sample.

  Options:
     -f   <Image>    Hibernation file to load
     -d   <outfile>  Raw output file
     -q              Dump only header information

ident
-----
For the given image, attempt to identify the operating system type,
virtual address translation mechanism, and a starting directory table
base (DTB). The output of ident can be used to speedup other commands
when using the -t and -b options with those commands. Options -t and
-b will be ignored when running ident itself.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    IGNORED
     -t   <type>    IGNORED

memdmp
-----
For each process running in the system, attempt to dump its
addressable storage. If -t and -b are not specified, Volatility 
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of EPROCESS object
     -p   <pid>     Pid of process

memmap
-----
For each process running in the system, attempt to dump its memory map. 
If -t and -b are not specified, Volatility will attempt to infer 
reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of EPROCESS object
     -p   <pid>     Pid of process

modscan
------
Scans the flat physical address space for kernel modules. If -t and -b are not specified, Volatility will attempt to infer reasonable values. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)

modules
-------
For the given image, list all kernel modules loaded at the time of
acquisition. If -t and -b are not specified, Volatility will
attempt to infer reasonable values. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)

procdump
-------
For each process in the given image, extract an executable sample. 
If -t and -b are not specified, Volatility will attempt to infer 
reasonable values. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of EPROCESS object
     -p   <pid>     Pid of process
     -m   <mode>    Strategy to use when extracting executable sample. Use
                    "disk" to save using disk-based section sizes or "mem"
                    for memory based sections (default": "mem").

pslist
------
For the given image, list all processes that were running, along with
some corresponding metadata such as process creation time. If -t and
-b are not specified, Volatility will attempt to infer reasonable
values.  

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)

psscan
------
Scans the flat physical address space for EPROCESS objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)
     -d             Print output in dot format

raw2dmp
-------
Convert a raw linear sample into a format that can be analyzed using
the Microsoft Windows Debugger (windbg).

  Options:
     -f   <Image>   Crash dump file to load
     -o   <outfile>  Raw output file

regobjkeys
-----
For each process running in the system, identify all open registry handles. 
If -t and -b are not specified, Volatility will attempt to infer 
reasonable values.

NOTE: files output may be very verbose. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of EPROCESS object
     -p   <pid>     Pid of process

sockets
-------
For the given image, list all open sockets registered with the kernel
and the corresponding process for which the socket was opened and
associated socket creation time. If -t and -b are not specified,
Volatility will attempt to infer reasonable values. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)

sockscan
------
Scans the flat physical address space for socket objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)

strings
-------
For a given image and a file with lines of the form <offset>:<string>,
output the corresponding process and virtual addresses where that
string can be found. Expected input for this tool is the output of
Microsoft Sysinternals' Strings utility, or another utility that
provides similarly formatted offset:string mappings. Note that the
input offsets are physical offsets from the start of the file/image. 
If -t and -b are not specified, Volatility will attempt to infer
reasonable values. 

NOTE: strings output may be very verbose.

  Options:
     -f   <Image>       Image file to load
     -s   <Stringfile>  File with lines of the form <offset>:<string>
     -b   <base>        Hexadecimal physical offset of valid Directory Table Base
     -t   <type>        Image type (pae, nopae, auto)

thrdscan
------
Scans the flat physical address space for ETHREAD objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)

vadwalk
-------

For the given image, print the Virtual Address Descriptors (VAD)
tree associated with a particular process. Depending on the command
line options the information will be printed in a number of different
formats. If -t and -b are not specified, Volatility will attempt
to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of a valid EPROCESS object
     -e             Print VAD tree in tree format
     -l             Print VAD tree in table format
     -d             Print VAD tree in Dot file format
     -p   <pid>     Extract VAD information of process with this pid

vadinfo
-------

For the given image, print detailed information about each object
found in the Virtual Address Descriptors (VAD) tree associated with a
particular process.  If -t and -b are not specified, Volatility
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of a valid EPROCESS object
     -p   <pid>     Extract VAD information of process with this pid

vaddump
-------

For the given image, traverse the Virtual Address Descriptors (VAD)
tree and dump the ranges of memory to files for further analysis. If
-t and -b are not specified, Volatility will attempt to infer
reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of a valid EPROCESS object
     -p   <pid>     Extract VAD information of process with this pid
