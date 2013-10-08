# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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

import volatility.obj as obj
import volatility.plugins.gui.constants as consts
import volatility.plugins.overlays.windows.windows as windows
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.conf as conf

#--------------------------------------------------------------------------------
# object classes
#--------------------------------------------------------------------------------

class _MM_SESSION_SPACE(obj.CType):
    """A class for session spaces"""

    def processes(self):
        """Generator for processes in this session. 
    
        A process is always associated with exactly
        one session.
        """
        for p in self.ProcessList.list_of_type("_EPROCESS", "SessionProcessLinks"):
            yield p

    @property
    def Win32KBase(self):
        """Get the base address of the win32k.sys as mapped 
        into this session's memory. 

        Since win32k.sys is always the first image to be 
        mapped, we can just grab the first list entry."""
        
        ## An exception may be generated when a process from a terminated
        ## session still exists in the active process list. 
        try:
            return list(self.images())[0].Address
        except IndexError:
            return obj.NoneObject("No images mapped in this session")

    def images(self):
        """Generator for images (modules) loaded into 
        this session's space"""
        for i in self.ImageList.list_of_type("_IMAGE_ENTRY_IN_SESSION", "Link"):
            yield i

    def _section_chunks(self, sec_name):
        """Get the win32k.sys section as an array of 
        32-bit unsigned longs. 

        @param sec_name: name of the PE section in win32k.sys 
        to search for. 

        @returns all chunks on a 4-byte boundary. 
        """
        
        dos_header = obj.Object("_IMAGE_DOS_HEADER",
                offset = self.Win32KBase, vm = self.obj_vm)
                
        if dos_header:
            try:
                nt_header = dos_header.get_nt_header()
        
                sections = [
                    sec for sec in nt_header.get_sections(False)
                    if str(sec.Name) == sec_name
                    ]
        
                # There should be exactly one section 
                if sections:
                    desired_section = sections[0]
                    return obj.Object("Array", targetType = "unsigned long",
                                        offset = desired_section.VirtualAddress + dos_header.obj_offset, 
                                        count = desired_section.Misc.VirtualSize / 4, 
                                        vm = self.obj_vm)
            except ValueError:
                ## This catches PE header parsing exceptions 
                pass
                
        ## Don't try to read an address that doesn't exist
        if not self.Win32KBase:
            return []

        ## In the rare case when win32k.sys PE header is paged or corrupted
        ## thus preventing us from parsing the sections, use the fallback
        ## mechanism of just reading 5 MB (max size of win32k.sys) from the 
        ## base of the kernel module. 
        data = self.obj_vm.zread(self.Win32KBase, 0x500000) 
        
        ## Fill a Buffer AS with the zread data and set its base to win32k.sys
        ## so we can still instantiate an Array and have each chunk at the 
        ## correct offset in virtual memory.
        buffer_as = addrspace.BufferAddressSpace(conf.ConfObject(), 
                                            data = data, 
                                            base_offset = self.Win32KBase)
                            
        return obj.Object("Array", targetType = "unsigned long", 
                          offset = self.Win32KBase, 
                          count = len(data) / 4, 
                          vm = buffer_as)

    def find_gahti(self):
        """Find this session's gahti. 

        This can potentially be much faster by searching for 
        '\0' * sizeof(tagHANDLETYPEINFO) instead 
        of moving on a dword aligned boundary through
        the section. 
        """

        for chunk in self._section_chunks(".rdata"):
            if not chunk.is_valid():
                continue

            gahti = obj.Object("gahti", offset = chunk.obj_offset,
                vm = self.obj_vm)

            ## The sanity check here is based on the fact that the first entry
            ## in the gahti is always for TYPE_FREE. The fnDestroy pointer will
            ## be NULL, the alloc tag will be an empty string, and the creation 
            ## flags will be zero. We also then check the alloc tag of the first
            ## USER handle type which should be Uswd (TYPE_WINDOW). 
            if (gahti.types[0].fnDestroy == 0 and
                    str(gahti.types[0].dwAllocTag) == '' and
                    gahti.types[0].bObjectCreateFlags == 0 and
                    str(gahti.types[1].dwAllocTag) == "Uswd"):
                return gahti

        return obj.NoneObject("Cannot find win32k!_gahti")

    def find_shared_info(self):
        """Find this session's tagSHAREDINFO structure. 

        This structure is embedded in win32k's .data section, 
        (i.e. not in dynamically allocated memory). Thus we 
        iterate over each DWORD-aligned possibility and treat 
        it as a tagSHAREDINFO until the sanity checks are met. 
        """

        for chunk in self._section_chunks(".data"):
            # If the base of the value is paged
            if not chunk.is_valid():
                continue
            # Treat it as a shared info struct 
            shared_info = obj.Object("tagSHAREDINFO",
                offset = chunk.obj_offset, vm = self.obj_vm)
            # Sanity check it 
            try:
                if shared_info.is_valid():
                    return shared_info
            except obj.InvalidOffsetError:
                pass

        return obj.NoneObject("Cannot find win32k!gSharedInfo")

class tagSHAREDINFO(obj.CType):
    """A class for shared info blocks"""

    def is_valid(self):
        """The sanity checks for tagSHAREDINFO structures"""

        if not obj.CType.is_valid(self):
            return False

        # The kernel's version of tagSHAREDINFO should always have
        # a zeroed-out shared delta member. 
        if self.ulSharedDelta != 0:
            return False

        # The pointer to our server information structure must be valid
        if not self.psi.is_valid():
            return False

        # Annoying check, but required for some samples 
        # whose psi is a valid pointer, but cbHandleTable
        # cannot be read due to objects that cross page 
        # boundaries. 
        if self.psi.cbHandleTable == None:
            return False

        if self.psi.cbHandleTable < 0x1000:
            return False

        # The final check is that the total size in bytes of the handle
        # table is equal to the size of a _HANDLEENTRY multiplied by the
        # number of _HANDLEENTRY structures. 
        return (self.psi.cbHandleTable /
                    self.obj_vm.profile.get_obj_size("_HANDLEENTRY")
                == self.psi.cHandleEntries)

    def handles(self, filters = None):
        """Carve handles from the shared info block. 

        @param filters: a list of callables that perform
        checks and return True if the handle should be
        included in output.
        """

        if filters == None:
            filters = []

        hnds = obj.Object("Array", targetType = "_HANDLEENTRY",
                            offset = self.aheList,
                            vm = self.obj_vm,
                            count = self.psi.cHandleEntries)

        for i, h in enumerate(hnds):

            # Sanity check the handle value if the handle Object
            # has not been freed. 
            if not h.Free:
                if h.phead.h != (h.wUniq << 16) | (0xFFFF & i):
                    continue

            b = False

            # Run the filters and break if any tests fail
            for filt in filters:
                if not filt(h):
                    b = True
                    break

            if not b:
                yield h

class _HANDLEENTRY(obj.CType):
    """A for USER handle entries"""

    def reference_object(self):
        """Reference the object this handle represents. 

        If the object's type is not in our map, we don't know
        what type of object to instantiate so its filled with
        obj.NoneObject() instead. 
        """

        object_map = dict(TYPE_WINDOW = "tagWND",
                        TYPE_HOOK = "tagHOOK",
                        TYPE_CLIPDATA = "tagCLIPDATA",
                        TYPE_WINEVENTHOOK = "tagEVENTHOOK",
                        TYPE_TIMER = "tagTIMER",
                        )

        object_type = object_map.get(str(self.bType), None)

        if not object_type:
            return obj.NoneObject("Cannot reference object type")

        return obj.Object(object_type,
                    offset = self.phead, vm = self.obj_vm)

    @property
    def Free(self):
        """Check if the handle has been freed"""
        return str(self.bType) == "TYPE_FREE"

    @property
    def ThreadOwned(self):
        """Handles of these types are always thread owned"""
        return str(self.bType) in [
                            'TYPE_WINDOW', 'TYPE_SETWINDOWPOS', 'TYPE_HOOK',
                            'TYPE_DDEACCESS', 'TYPE_DDECONV', 'TYPE_DDEXACT',
                            'TYPE_WINEVENTHOOK', 'TYPE_INPUTCONTEXT', 'TYPE_HIDDATA',
                            'TYPE_TOUCH', 'TYPE_GESTURE']
    @property
    def ProcessOwned(self):
        """Handles of these types are always process owned"""
        return str(self.bType) in [
                                'TYPE_MENU', 'TYPE_CURSOR', 'TYPE_TIMER',
                                'TYPE_CALLPROC', 'TYPE_ACCELTABLE']
    @property
    def Thread(self):
        """Return the ETHREAD if its thread owned"""
        if self.ThreadOwned:
            return self.pOwner.\
                        dereference_as("tagTHREADINFO").\
                        pEThread.dereference()
        return obj.NoneObject("Cannot find thread")

    @property
    def Process(self):
        """Return the _EPROCESS if its process or thread owned"""
        if self.ProcessOwned:
            return self.pOwner.\
                        dereference_as("tagPROCESSINFO").\
                        Process.dereference()
        elif self.ThreadOwned:
            return self.pOwner.\
                        dereference_as("tagTHREADINFO").\
                        ppi.Process.dereference()
        return obj.NoneObject("Cannot find process")

class tagWINDOWSTATION(obj.CType):
    """A class for Windowstation objects"""

    def is_valid(self):
        return obj.CType.is_valid(self) and self.dwSessionId < 0xFF

    @property
    def PhysicalAddress(self):
        """This is a simple wrapper to always return the object's
        physical offset regardless of what AS its instantiated in"""
        if hasattr(self.obj_vm, "vtop"):
            return self.obj_vm.vtop(self.obj_offset)
        else:
            return self.obj_offset

    @property
    def LastRegisteredViewer(self):
        """The EPROCESS of the last registered 
        clipboard viewer"""
        return self.spwndClipViewer.head.pti.ppi.Process

    @property
    def AtomTable(self):
        """This atom table belonging to this window 
        station object"""
        return self.pGlobalAtomTable.dereference_as("_RTL_ATOM_TABLE")

    @property
    def Interactive(self):
        """Check if a window station is interactive"""
        return not self.dwWSF_Flags & 4 # WSF_NOIO

    @property
    def Name(self):
        """Get the window station name. 

        Since window stations are securable objects, 
        and are managed by the same object manager as
        processes, threads, etc, there is an object
        header which stores the name.
        """

        object_hdr = obj.Object("_OBJECT_HEADER",
            vm = self.obj_vm, offset = self.obj_offset - \
            self.obj_vm.profile.get_obj_offset('_OBJECT_HEADER', 'Body'),
            native_vm = self.obj_native_vm)

        return str(object_hdr.NameInfo.Name or '')

    def traverse(self):
        """A generator that yields window station objects"""

        # Include this object in the results
        yield self
        # Now walk the singly-linked list 
        nextwinsta = self.rpwinstaNext.dereference()
        while nextwinsta.is_valid() and nextwinsta.v() != 0:
            yield nextwinsta
            nextwinsta = nextwinsta.rpwinstaNext.dereference()

    def desktops(self):
        """A generator that yields the window station's desktops"""
        desk = self.rpdeskList.dereference()
        while desk.is_valid() and desk.v() != 0:
            yield desk
            desk = desk.rpdeskNext.dereference()

class tagDESKTOP(tagWINDOWSTATION):
    """A class for Desktop objects"""

    def is_valid(self):
        return (obj.CType.is_valid(self) and self.dwSessionId < 0xFF)

    @property
    def WindowStation(self):
        """Returns this desktop's parent window station"""
        return self.rpwinstaParent.dereference()

    @property
    def DeskInfo(self):
        """Returns the desktop info object"""
        return self.pDeskInfo.dereference()

    def threads(self):
        """Generator for _EPROCESS objects attached to this desktop"""
        for ti in self.PtiList.list_of_type("tagTHREADINFO", "PtiLink"):
            yield ti

    def hook_params(self):
        """ Parameters for the hooks() method.

        These are split out into a function so it can be 
        subclassed by tagTHREADINFO.
        """
        return (self.DeskInfo.fsHooks, self.DeskInfo.aphkStart)

    def hooks(self):
        """Generator for tagHOOK info. 
        
        Hooks are carved using the same algorithm, but different
        starting points for desktop hooks and thread hooks. Thus
        the algorithm is presented in this function and the starting
        point is acquired by calling hook_params (which is then sub-
        classed by tagTHREADINFO. 
        """

        (fshooks, aphkstart) = self.hook_params()

        # Convert the WH_* index into a bit position for the fsHooks fields 
        WHF_FROM_WH = lambda x: (1 << x + 1)

        for pos, (name, value) in enumerate(consts.MESSAGE_TYPES):
            # Is the bit for this WH_* value set ? 
            if fshooks & WHF_FROM_WH(value):
                hook = aphkstart[pos].dereference()
                for hook in hook.traverse():
                    yield name, hook

    def windows(self, win, filter = lambda x: True, level = 0): #pylint: disable-msg=W0622
        """Traverses windows in their Z order, bottom to top.

        @param win: an HWND to start. Usually this is the desktop 
        window currently in focus. 

        @param filter: a callable (usually lambda) to use for filtering
        the results. See below for examples:

        # only print subclassed windows
        filter = lambda x : x.lpfnWndProc == x.pcls.lpfnWndProc

        # only print processes named csrss.exe
        filter = lambda x : str(x.head.pti.ppi.Process.ImageFileName).lower() \
                                == "csrss.exe" if x.head.pti.ppi else False

        # only print processes by pid
        filter = lambda x : x.head.pti.pEThread.Cid.UniqueThread == 0x1020

        # only print visible windows
        filter = lambda x : 'WS_VISIBLE' not in x.get_flags() 
        """
        seen = set()
        wins = []
        cur = win
        while cur.is_valid() and cur.v() != 0:
            if cur in seen:
                break
            seen.add(cur)
            wins.append(cur)
            cur = cur.spwndNext.dereference()
        while wins:
            cur = wins.pop()
            if not filter(cur):
                continue

            yield cur, level

            if cur.spwndChild.is_valid() and cur.spwndChild.v() != 0:
                for info in self.windows(cur.spwndChild, filter = filter, level = level + 1):
                    yield info

    def heaps(self):
        """Generator for the desktop heaps"""
        for segment in self.pheapDesktop.Heap.segments():
            for entry in segment.heap_entries():
                yield entry

    def traverse(self):
        """Generator for next desktops in the list"""

        # Include this object in the results 
        yield self
        # Now walk the singly-linked list
        nextdesk = self.rpdeskNext.dereference()
        while nextdesk.is_valid() and nextdesk.v() != 0:
            yield nextdesk
            nextdesk = nextdesk.rpdeskNext.dereference()

class tagWND(obj.CType):
    """A class for window structures"""

    @property
    def IsClipListener(self):
        """Check if this window listens to clipboard changes"""
        return self.bClipboardListener.v()

    @property
    def ClassAtom(self):
        """The class atom for this window"""
        return self.pcls.atomClassName

    @property
    def SuperClassAtom(self):
        """The window's super class"""
        return self.pcls.atomNVClassName

    @property
    def Process(self):
        """The EPROCESS that owns the window"""
        return self.head.pti.ppi.Process.dereference()

    @property
    def Thread(self):
        """The ETHREAD that owns the window"""
        return self.head.pti.pEThread.dereference()

    @property
    def Visible(self):
        """Is this window visible on the desktop"""
        return 'WS_VISIBLE' in self.style

    def _get_flags(self, member, flags):

        if flags.has_key(member):
            return flags[member]

        return ','.join([n for (n, v) in flags.items() if member & v == v])

    @property
    def style(self):
        """The basic style flags as a string"""
        return self._get_flags(self.m('style').v(), consts.WINDOW_STYLES)

    @property
    def ExStyle(self):
        """The extended style flags as a string"""
        return self._get_flags(self.m('ExStyle').v(), consts.WINDOW_STYLES_EX)

class tagRECT(obj.CType):
    """A class for window rects"""

    def get_tup(self):
        """Return a tuple of the rect's coordinates"""
        return (self.left, self.top, self.right, self.bottom)

class tagCLIPDATA(obj.CType):
    """A class for clipboard objects"""

    def as_string(self, fmt):
        """Format the clipboard data as a string. 

        @param fmt: the clipboard format. 

        Note: we cannot simply override __str__ for this
        purpose, because the clipboard format is not a member 
        of (or in a parent-child relationship with) the 
        tagCLIPDATA structure, so we must pass it in as 
        an argument. 
        """

        if fmt == "CF_UNICODETEXT":
            encoding = "utf16"
        else:
            encoding = "utf8"

        return obj.Object("String", offset = self.abData.obj_offset,
                        vm = self.obj_vm, encoding = encoding,
                        length = self.cbData)

    def as_hex(self):
        """Format the clipboard contents as a hexdump"""
        data = ''.join([chr(c) for c in self.abData])
        return "".join(["{0:#x}  {1:<48}  {2}\n".format(self.abData.obj_offset + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(data)])

class tagTHREADINFO(tagDESKTOP):
    """A class for thread information objects"""

    def get_params(self):
        """Parameters for the _hooks() function"""
        return (self.fsHooks, self.aphkStart)

class tagHOOK(obj.CType):
    """A class for message hooks"""

    def traverse(self):
        """Find the next hook in a chain"""
        hook = self
        while hook.is_valid() and hook.v() != 0:
            yield hook
            hook = hook.phkNext.dereference()

class tagEVENTHOOK(obj.CType):
    """A class for event hooks"""

    @property
    def dwFlags(self):
        """Event hook flags need special handling so we can't use vtypes"""

        # First we shift the value 
        f = self.m('dwFlags') >> 1

        flags = [name for (val, name) in consts.EVENT_FLAGS.items() if f & val == val]

        return '|'.join(flags)

class _RTL_ATOM_TABLE(tagWINDOWSTATION):
    """A class for atom tables"""

    def __init__(self, *args, **kwargs):
        """Give ourselves an atom cache for quick lookups"""
        self.atom_cache = {}
        tagWINDOWSTATION.__init__(self, *args, **kwargs)

    def is_valid(self):
        """Check for validity based on the atom table signature
        and the maximum allowed number of buckets"""
        return (obj.CType.is_valid(self) and
                    self.Signature == 0x6d6f7441 and
                    self.NumBuckets < 0xFFFF)

    def atoms(self):
        """Carve all atoms out of this atom table"""
        # The default hash buckets should be 0x25 
        for bkt in self.Buckets:
            cur = bkt.dereference()
            while cur.is_valid() and cur.v() != 0:
                yield cur
                cur = cur.HashLink.dereference()

    def find_atom(self, atom_to_find):
        """Find an atom by its ID. 

        @param atom_to_find: the atom ID (ushort) to find

        @returns an _RTL_ATOM_TALE_ENTRY object 
        """

        # Use the cached results if they exist 
        if self.atom_cache:
            return self.atom_cache.get(atom_to_find.v(), None)

        # Build the atom cache 
        self.atom_cache = dict(
                (atom.Atom.v(), atom) for atom in self.atoms())

        return self.atom_cache.get(atom_to_find.v(), None)

class _RTL_ATOM_TABLE_ENTRY(obj.CType):
    """A class for atom table entries"""

    @property
    def Pinned(self):
        """Returns True if the atom is pinned"""
        return self.Flags == 1

    def is_string_atom(self):
        """Returns True if the atom is a string atom 
        based on its atom ID. 
        
        A string atom has ID 0xC000 - 0xFFFF
        """
        return self.Atom >= 0xC000 and self.Atom <= 0xFFFF

    def is_valid(self):
        """Perform some sanity checks on the Atom"""
        if not obj.CType.is_valid(self):
            return False
        # There is only one flag (and zero)
        if self.Flags not in (0, 1):
            return False
        # There is a maximum name length enforced
        return self.NameLength <= 255

#--------------------------------------------------------------------------------
# profile modifications
#--------------------------------------------------------------------------------

class Win32KCoreClasses(obj.ProfileModification):
    """Apply the core object classes"""

    before = ["WindowsObjectClasses"]

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):

        profile.object_classes.update({
            'tagWINDOWSTATION': tagWINDOWSTATION,
            'tagDESKTOP': tagDESKTOP,
            '_RTL_ATOM_TABLE': _RTL_ATOM_TABLE,
            '_RTL_ATOM_TABLE_ENTRY': _RTL_ATOM_TABLE_ENTRY,
            'tagTHREADINFO': tagTHREADINFO,
            'tagHOOK': tagHOOK,
            '_LARGE_UNICODE_STRING': windows._UNICODE_STRING, #pylint: disable-msg=W0212
            'tagWND': tagWND,
            '_MM_SESSION_SPACE': _MM_SESSION_SPACE,
            'tagSHAREDINFO': tagSHAREDINFO,
            '_HANDLEENTRY': _HANDLEENTRY,
            'tagEVENTHOOK': tagEVENTHOOK,
            'tagRECT': tagRECT,
            'tagCLIPDATA': tagCLIPDATA,
            })

class Win32KGahtiVType(obj.ProfileModification):
    """Apply a vtype for win32k!gahti. Adjust the number of 
    handles according to the OS version"""

    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):

        version = (profile.metadata.get('major', 0), profile.metadata.get('minor', 0))

        ## Windows 7 and above 
        if version >= (6, 1):
            num_handles = len(consts.HANDLE_TYPE_ENUM_SEVEN)
        else:
            num_handles = len(consts.HANDLE_TYPE_ENUM)

        profile.vtypes.update({
            'gahti' : [ None, {
            'types': [ 0, ['array', num_handles, ['tagHANDLETYPEINFO']]],
            }]})

class AtomTablex86Overlay(obj.ProfileModification):
    """Apply the atom table overlays for all x86 Windows"""

    before = ["WindowsVTypes"]

    conditions = {'os': lambda x: x == 'windows',
                'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        # The type we want to use is not the same as the one already defined
        # see http://code.google.com/p/volatility/issues/detail?id=131
        profile.merge_overlay({
            '_RTL_ATOM_TABLE': [ None, {
            'Signature': [ 0x0, ['unsigned long']],
            'NumBuckets': [ 0xC, ['unsigned long']],
            'Buckets': [ 0x10, ['array', lambda x : x.NumBuckets,
                ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]]],
            }],
            '_RTL_ATOM_TABLE_ENTRY': [ None, {
            'Name': [ None, ['String', dict(encoding = 'utf16',
                length = lambda x : x.NameLength * 2)]],
            }]})

class AtomTablex64Overlay(obj.ProfileModification):
    """Apply the atom table overlays for all x64 Windows"""

    conditions = {'os': lambda x: x == 'windows',
                'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        # The type we want to use is not the same as the one already defined
        # see http://code.google.com/p/volatility/issues/detail?id=131
        profile.merge_overlay({
            '_RTL_ATOM_TABLE': [ None, {
            'Signature': [ 0, ['unsigned long']],
            'NumBuckets': [ 0x18, ['unsigned long']],
            'Buckets': [ 0x20, ['array', lambda x : x.NumBuckets,
                ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]]],
            }],
            '_RTL_ATOM_TABLE_ENTRY': [ None, {
            'Name': [ None, ['String', dict(encoding = 'utf16',
                length = lambda x : x.NameLength * 2)]],
            }]})

class XP2003x86TimerVType(obj.ProfileModification):
    """Apply the tagTIMER for XP and 2003 x86"""

    conditions = {'os': lambda x: x == 'windows',
                 'memory_model': lambda x: x == '32bit',
                 'major': lambda x: x < 6}

    def modification(self, profile):
        # http://doxygen.reactos.org/d5/dd0/timer_8h_source.html#l00019
        profile.vtypes.update({
            'tagTIMER' : [ None, {
            'head' : [ 0x00, ['_HEAD']],
            'ListEntry' : [ 0x08, ['_LIST_ENTRY']],
            'pti' : [ 0x10, ['pointer', ['tagTHREADINFO']]],
            'spwnd' : [ 0x14, ['pointer', ['tagWND']]],
            'nID' : [ 0x18, ['unsigned short']],
            'cmsCountdown' : [ 0x1C, ['unsigned int']],
            'cmsRate' : [ 0x20, ['unsigned int']],
            'flags' : [ 0x24, ['Flags', {'bitmap': consts.TIMER_FLAGS}]],
            'pfn' : [ 0x28, ['pointer', ['void']]],
            }]})

class XP2003x64TimerVType(obj.ProfileModification):
    """Apply the tagTIMER for XP and 2003 x64"""

    conditions = {'os': lambda x: x == 'windows',
                 'memory_model': lambda x: x == '64bit',
                 'major': lambda x: x < 6}

    def modification(self, profile):
        profile.vtypes.update({
            # http://doxygen.reactos.org/d5/dd0/timer_8h_source.html#l00019
            'tagTIMER' : [ None, {
            'head' : [ 0x00, ['_HEAD']],
            'ListEntry' : [ 0x18, ['_LIST_ENTRY']],
            'spwnd' : [ 0x28, ['pointer', ['tagWND']]],
            'pti' : [ 0x20, ['pointer', ['tagTHREADINFO']]],
            'nID' : [ 0x30, ['unsigned short']],
            'cmsCountdown' : [ 0x38, ['unsigned int']],
            'cmsRate' : [ 0x3C, ['unsigned int']],
            'flags' : [ 0x40, ['Flags', {'bitmap': consts.TIMER_FLAGS}]],
            'pfn' : [ 0x48, ['pointer', ['void']]],
            }]})

class Win32Kx86VTypes(obj.ProfileModification):
    """Applies to all x86 windows profiles. 

    These are vtypes not included in win32k.sys PDB.
    """

    conditions = {'os': lambda x: x == 'windows',
                'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        profile.vtypes.update({
            'tagWIN32HEAP': [ None, {
            'Heap': [ 0, ['_HEAP']],
            }],
            'tagCLIPDATA' : [ None, {
            'cbData' : [ 0x08, ['unsigned int']],
            'abData' : [ 0x0C, ['array', lambda x: x.cbData, ['unsigned char']]],
            }],
            '_IMAGE_ENTRY_IN_SESSION': [ None, {
            'Link': [ 0, ['_LIST_ENTRY']],
            'Address': [ 8, ['pointer', ['address']]],
            'LastAddress': [ 12, ['pointer', ['address']]],
            # This is optional and usually supplied as null
            'DataTableEntry': [ 24, ['pointer', ['_LDR_DATA_TABLE_ENTRY']]],
            }],
            'tagEVENTHOOK' : [ 0x30, {
            'phkNext' : [ 0xC, ['pointer', ['tagEVENTHOOK']]],
            'eventMin' : [ 0x10, ['Enumeration', dict(target = 'unsigned long', choices = consts.EVENT_ID_ENUM)]],
            'eventMax' : [ 0x14, ['Enumeration', dict(target = 'unsigned long', choices = consts.EVENT_ID_ENUM)]],
            'dwFlags' : [ 0x18, ['unsigned long']],
            'idProcess' : [ 0x1C, ['unsigned long']],
            'idThread' : [ 0x20, ['unsigned long']],
            'offPfn' : [ 0x24, ['unsigned long']],
            'ihmod' : [ 0x28, ['long']],
            }],
            'tagHANDLETYPEINFO' : [ 12, {
            'fnDestroy' : [ 0, ['pointer', ['void']]],
            'dwAllocTag' : [ 4, ['String', dict(length = 4)]],
            'bObjectCreateFlags' : [ 8, ['Flags', {'target': 'unsigned char', 'bitmap': {'OCF_THREADOWNED': 0, 'OCF_PROCESSOWNED': 1, 'OCF_MARKPROCESS': 2, 'OCF_USEPOOLQUOTA': 3, 'OCF_DESKTOPHEAP': 4, 'OCF_USEPOOLIFNODESKTOP': 5, 'OCF_SHAREDHEAP': 6, 'OCF_VARIABLESIZE': 7}}]],
            }],
        })

class Win32Kx64VTypes(obj.ProfileModification):
    """Applies to all x64 windows profiles. 

    These are vtypes not included in win32k.sys PDB.
    """

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit'}

    def modification(self, profile):
        # Autogen'd vtypes from win32k.sys do not contain these
        profile.vtypes.update({
            'tagWIN32HEAP': [ None, {
            'Heap': [ 0, ['_HEAP']],
            }],
            '_IMAGE_ENTRY_IN_SESSION': [ None, {
            'Link': [ 0, ['_LIST_ENTRY']],
            'Address': [ 0x10, ['pointer', ['void']]],
            'LastAddress': [ 0x18, ['pointer', ['address']]],
            # This is optional and usually supplied as null
            'DataTableEntry': [ 0x20, ['pointer', ['_LDR_DATA_TABLE_ENTRY']]], #??
            }],
            'tagCLIPDATA' : [ None, {
            'cbData' : [ 0x10, ['unsigned int']],
            'abData' : [ 0x14, ['array', lambda x: x.cbData, ['unsigned char']]],
            }],
            'tagEVENTHOOK' : [ None, {
            'phkNext' : [ 0x18, ['pointer', ['tagEVENTHOOK']]],
            'eventMin' : [ 0x20, ['Enumeration', dict(target = 'unsigned long', choices = consts.EVENT_ID_ENUM)]],
            'eventMax' : [ 0x24, ['Enumeration', dict(target = 'unsigned long', choices = consts.EVENT_ID_ENUM)]],
            'dwFlags' : [ 0x28, ['unsigned long']],
            'idProcess' : [ 0x2C, ['unsigned long']],
            'idThread' : [ 0x30, ['unsigned long']],
            'offPfn' : [ 0x40, ['unsigned long long']],
            'ihmod' : [ 0x48, ['long']],
            }],
            'tagHANDLETYPEINFO' : [ 16, {
            'fnDestroy' : [ 0, ['pointer', ['void']]],
            'dwAllocTag' : [ 8, ['String', dict(length = 4)]],
            'bObjectCreateFlags' : [ 12, ['Flags', {'target': 'unsigned char', 'bitmap': {'OCF_THREADOWNED': 0, 'OCF_PROCESSOWNED': 1, 'OCF_MARKPROCESS': 2, 'OCF_USEPOOLQUOTA': 3, 'OCF_DESKTOPHEAP': 4, 'OCF_USEPOOLIFNODESKTOP': 5, 'OCF_SHAREDHEAP': 6, 'OCF_VARIABLESIZE': 7}}]],
            }],
        })

class XPx86SessionOverlay(obj.ProfileModification):
    """Apply the ResidentProcessCount overlay for x86 XP session spaces"""

    ## This just ensures we have an _MM_SESSION_SPACE to overlay
    before = ["WindowsOverlay"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 1}

    def modification(self, profile):
        # This field appears in the auto-generated vtypes for all OS except XP
        profile.merge_overlay({
            '_MM_SESSION_SPACE': [ None, {
            'ResidentProcessCount': [ 0x248, ['long']], # nt!MiDereferenceSession
            }]})




