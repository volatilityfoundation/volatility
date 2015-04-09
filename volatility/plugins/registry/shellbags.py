# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012 Jamie Levy (Gleeda) <jamie@memoryanalysis.net>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie@memoryanalysis.net
@organization: Volatility Foundation
"""


import volatility.utils as utils
import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.obj as obj
import volatility.addrspace as addrspace
import volatility.plugins.overlays.basic as basic
import volatility.timefmt as timefmt
from volatility.renderers import TreeGrid
import struct
import datetime 

'''
Some references for further reading, all of which were used for building this plugin:

http://download.polytechnic.edu.na/pub4/download.sourceforge.net/pub/sourceforge/l/project/li/liblnk/Documentation/Windows%20Shell%20Item%20format/Windows%20Shell%20Item%20format.pdf
    Windows Shell Item format specification (pdf) by Joachim Metz
http://www.dfrws.org/2009/proceedings/p69-zhu.pdf
    Using shellbag information to reconstruct user activities (pdf) by Yuandong Zhu, Pavel Gladyshev and Joshua James
http://www.williballenthin.com/forensics/shellbags/index.html
    Windows shellbag forensics by Willi Ballenthin
http://code.google.com/p/registrydecoder/source/browse/trunk/templates/template_files/ShellBagMRU.py
    ShellBagMRU.py from Registry Decoder by Kevin Moore
http://code.google.com/p/regripper/wiki/ShellBags
    Shellbags RegRipper plugin by Harlan Carvey
'''


EXT_VERSIONS = {
    "0x0003":"Windows XP",
    "0x0007":"Windows Vista",
    "0x0008":"Windows 7",
}

# http://support.microsoft.com/kb/813711
BAG_KEYS = [
    "Software\\Microsoft\\Windows\\Shell",
    "Software\\Microsoft\\Windows\\ShellNoRoam",
]

USERDAT_KEYS = [
    "Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
    "Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell",
    "Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
]

# These are abbreviated only because there can be more than one in output
# so it gets cluttered
FILE_ATTRS = {
    0x00000001:"RO",        #Is read-Only
    0x00000002:"HID",       #Is hidden
    0x00000004:"SYS",       #Is a system file or directory
    0x00000008:"VOL",       #Is a volume label
    0x00000010:"DIR",       #Is a directory
    0x00000020:"ARC",       #Should be archived
    0x00000040:"DEV",       #Is a device
    0x00000080:"NORM",      #Is normal None of the other flags should be set
    0x00000100:"TEMP",      #Is temporary
    0x00000200:"SPARSE",    #Is a sparse file
    0x00000400:"RP",        #Is a reparse point or symbolic link
    0x00000800:"COM",       #Is compressed
    0x00001000:"OFFLINE",   #Is offline The data of the file is stored on an offline storage.
    0x00002000:"NI",        #Do not index content The content of the file or directory should not be indexed by the indexing service.
    0x00004000:"ENC",       #Is encrypted
    0x00010000:"VIR",       #Is virtual
}

# GUIDs and FOLDER_IDs copied from Will Ballenthin's shellbags parser: 
# https://github.com/williballenthin/shellbags

KNOWN_GUIDS = {
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "CSIDL_SYSTEM",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "{Unknown CSIDL}",
    "22877a6d-37a1-461a-91b0-dbda5aaebc99": "{Unknown CSIDL}",
    "2400183a-6185-49fb-a2d8-4a392a602ba3": "Public Videos",
    "2559a1f1-21d7-11d4-bdaf-00c04f60b9f0": "{Unknown CSIDL}",
    "2559a1f3-21d7-11d4-bdaf-00c04f60b9f0": "{Unknown CSIDL}",
    "26ee0668-a00a-44d7-9371-beb064c98683": "{Unknown CSIDL}",
    "3080f90e-d7ad-11d9-bd98-0000947b0257": "{Unknown CSIDL}",
    "3214fab5-9757-4298-bb61-92a9deaa44ff": "Public Music",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "4336a54d-038b-4685-ab02-99bb52d3fb8b": "{Unknown CSIDL}",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "5399e694-6ce5-4d6c-8fce-1d8870fdcba0": "Control Panel",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "724ef170-a42d-4fef-9f26-b60e846fba4f": "Administrative Tools",
    "7b0db17d-9cd2-4a93-9733-46cc89022e7c": "Documents Library",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "Program Files (x86)",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer (Homepage)",
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": "Program Files",
    "9e52ab10-f80d-49df-acb8-4330f5687855": "Temporary Burn Folder",
    "a305ce99-f527-492b-8b1a-7e76fa98d6e4": "Installed Updates",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "b6ebfb86-6907-413c-9af7-4fc2abf07cc5": "Public Pictures",
    "c1bae2d0-10df-4334-bedd-7aa20b227a9d": "Common OEM Links",
    "cce6191f-13b2-44fa-8d14-324728beef2c": "{Unknown CSIDL}",
    "d0384e7d-bac3-4797-8f14-cba229b392b5": "Common Administrative Tools",
    "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27": "System32 (x86)",
    "de61d971-5ebc-4f02-a3a9-6c82895e5c04": "Get Programs",
    "df7266ac-9274-4867-8d55-3bd661de872d": "Programs and Features",
    "dfdf76a2-c82a-4d63-906a-5644ac457385": "Public",
    "de974d24-d9c6-4d3e-bf91-f4455120b917": "Common Files",
    "ed228fdf-9ea8-4870-83b1-96b02cfe0d52": "My Games",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network", 
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "f3ce0f7c-4901-4acc-8648-d5d44b04ef8f": "Users Files",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    # Control Panel Items
    "d20ea4e1-3957-11d2-a40b-0c5020524153": "Administrative Tools",
    "9c60de1e-e5fc-40f4-a487-460851a8d915": "AutoPlay",
    "d9ef8727-cac2-4e60-809e-86f80a666c91": "BitLocker Drive Encryption",
    "b2c761c6-29bc-4f19-9251-e6195265baf1": "Color Management",
    "e2e7934b-dce5-43c4-9576-7fe4f75e7480": "Date and Time",
    "17cd9488-1228-4b2f-88ce-4298e93e0966": "Default Programs",
    "74246bfc-4c96-11d0-abef-0020af6b0b7a": "Device Manager",
    "d555645e-d4f8-4c29-a827-d93c859c4f2a": "Ease of Access Center",
    "6dfd7c5c-2451-11d3-a299-00c04f8ef6af": "Folder Options",
    "93412589-74d4-4e4e-ad0e-e0cb621440fd": "Fonts",
    "259ef4b1-e6c9-4176-b574-481532c9bce8": "Game Controllers",
    "15eae92e-f17a-4431-9f28-805e482dafd4": "Get Programs",
    "87d66a43-7b11-4a28-9811-c86ee395acf7": "Indexing Options",
    "a3dd4f92-658a-410f-84fd-6fbbbef2fffe": "Internet Options",
    "a304259d-52b8-4526-8b1a-a1d6cecc8243": "iSCSI Initiator",
    "725be8f7-668e-4c7b-8f90-46bdb0936430": "Keyboard",
    "6c8eec18-8d75-41b2-a177-8831d59d2d50": "Mouse",
    "8e908fc9-becc-40f6-915b-f4ca0e70d03d": "Network and Sharing Center",
    "d24f75aa-4f2b-4d07-a3c4-469b3d9030c4": "Offline Files",
    "96ae8d84-a250-4520-95a5-a47a7e3c548b": "Parental Controls",
    "5224f545-a443-4859-ba23-7b5a95bdc8ef": "People Near Me",
    "78f3955e-3b90-4184-bd14-5397c15f1efc": "Performance Information and Tools",
    "ed834ed6-4b5a-4bfe-8f11-a626dcb6a921": "Personalization",
    "025a5937-a6be-4686-a844-36fe4bec8b6d": "Power Options",
    "7b81be6a-ce2b-4676-a29e-eb907a5126c5": "Programs and Features",
    "00f2886f-cd64-4fc9-8ec5-30ef6cdbe8c3": "Scanners and Cameras",
    "9c73f5e5-7ae7-4e32-a8e8-8d23b85255bf": "Sync Center",
    "bb06c0e4-d293-4f75-8a90-cb05b6477eee": "System ",
    "80f3f1d5-feca-45f3-bc32-752c152e456e": "Tablet PC Settings",
    "0df44eaa-ff21-4412-828e-260a8728e7f1": "Taskbar and Start Menu",
    "d17d1d6d-cc3f-4815-8fe3-607e7d5d10b3": "Text to Speech",
    "60632754-c523-4b62-b45c-4172da012619": "User Accounts",
    "be122a0e-4503-11da-8bde-f66bad1e3f3a": "Windows Anytime Upgrade",
    "78cb147a-98ea-4aa6-b0df-c8681f69341c": "Windows CardSpace",
    "d8559eb9-20c0-410e-beda-7ed416aecc2a": "Windows Defender",
    "4026492f-2f69-46b8-b9bf-5654fc07e423": "Windows Firewall",
    "5ea4f148-308c-46d7-98a9-49041b1dd468": "Windows Mobility Center",
    "e95a4861-d57a-4be1-ad0f-35267e261739": "Windows SideShow",
    "36eef7db-88ad-4e81-ad49-0e313f0c35f8": "Windows Update",
    # Vista Control Panel Items
    "7a979262-40ce-46ff-aeee-7884ac3b6136": "Add Hardware",
    "f2ddfc82-8f12-4cdd-b7dc-d4fe1425aa4d": "Sound",
    "b98a2bea-7d42-4558-8bd1-832f41bac6fd": "Backup and Restore Center",
    "3e7efb4c-faf1-453d-89eb-56026875ef90": "Windows Marketplace",
    "a0275511-0e86-4eca-97c2-ecd8f1221d08": "Infrared",
    "f82df8f7-8b9f-442e-a48c-818ea735ff9b": "Pen and Input Devices",
    "40419485-c444-4567-851a-2dd7bfa1684d": "Phone and Modem",
    "2227a280-3aea-1069-a2de-08002b30309d": "Printers",
    "fcfeecae-ee1b-4849-ae50-685dcf7717ec": "Problem Reports and Solutions",
    "62d8ed13-c9d0-4ce8-a914-47dd628fb1b0": "Regional and Language Options",
    "087da31b-0dd3-4537-8e23-64a18591f88b": "Windows Security Center",
    "58e3c745-d971-4081-9034-86e34b30836a": "Speech Recognition Options",
    # Windows 7 Control Panel Items
    "bb64f8a7-bee7-4e1a-ab8d-7d8273f7fdb6": "Action Center",
    "0142e4d0-fb7a-11dc-ba4a-000ffe7ab428": "Biometric Devices",
    "1206f5f1-0569-412c-8fec-3204630dfb70": "Credential Manager",
    "00c6d95f-329c-409a-81d7-c46c66ea7f33": "Default Location",
    "37efd44d-ef8d-41b1-940d-96973a50e9e0": "Desktop Gadgets",
    "a8a91a66-3a7d-4424-8d24-04e180695c7a": "Devices and Printers",
    "c555438b-3c23-4769-a71f-b6d3d9b6053a": "Display",
    "cb1b7f8c-c50a-4176-b604-9e24dee8d4d1": "Getting Started",
    "67ca7650-96e6-4fdd-bb43-a8e774f73a57": "HomeGroup",
    "e9950154-c418-419e-a90a-20c5287ae24b": "Location and Other Sensors",
    "05d7b0f4-2121-4eff-bf6b-ed3f69b894d9": "Notification Area Icons",
    "9fe63afd-59cf-4419-9775-abcc3849f861": "Recovery",
    "241d7c96-f8bf-4f85-b01f-e2b043341a4b": "RemoteApp and Desktop Connections",
    "c58c4893-3be0-4b45-abb5-a63e4b8c8651": "Troubleshooting",
    # Folder Types
    "0b2baaeb-0042-4dca-aa4d-3ee8648d03e5": "Pictures Library",
    "36011842-dccc-40fe-aa3d-6177ea401788": "Documents Search Results",
    "3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b": "Music Library",
    "4dcafe13-e6a7-4c28-be02-ca8c2126280d": "Pictures Search Results",
    "5c4f28b5-f869-4e84-8e60-f11db97c5cc7": "Generic (All folder items)",
    "5f4eab9a-6833-4f61-899d-31cf46979d49": "Generic Library",
    "5fa96407-7e77-483c-ac93-691d05850de8": "Videos",
    "631958a6-ad0f-4035-a745-28ac066dc6ed": "Videos Library",
    "71689ac1-cc88-45d0-8a22-2943c3e7dfb3": "Music Search Results",
    "7d49d726-3c21-4f05-99aa-fdc2c9474656": "Documents",
    "7fde1a1e-8b31-49a5-93b8-6be14cfa4943": "Generic Search Results",
    "80213e82-bcfd-4c4f-8817-bb27601267a9": "Compressed Folder (zip folder)",
    "94d6ddcc-4a68-4175-a374-bd584a510b78": "Music",
    "b3690e58-e961-423b-b687-386ebfd83239": "Pictures",
    "ea25fbd7-3bf7-409e-b97f-3352240903f4": "Videos Search Results",
    "fbb3477e-c9e4-4b3b-a2ba-d3f5d3cd46f9": "Documents Library",
}

FOLDER_IDS = {
    0x00:"EXPLORER",
    0x42:"LIBRARIES",
    0x44:"USERS",
    0x48:"MY_DOCUMENTS",
    0x50:"MY_COMPUTER",
    0x58:"NETWORK",
    0x60:"RECYCLE_BIN",
    0x68:"EXPLORER",
    0x70:"UKNOWN",
    0x78:"RECYCLE_BIN",
    0x80:"MY_GAMES",
}

SHELL_ITEM_TYPES = {
    0x00:"UNKNOWN_00",              #Varied
    0x01:"UNKNOWN_01",
    0x2e:"UNKNOWN_2E",              # DEVICE from ShellBagMRU.py in RegistryDecoder
    0x31:"FILE_ENTRY",              # Folder
    0x32:"FILE_ENTRY",              # Zip file
    0xb1:"FILE_ENTRY",              # Hidden folder
    0x1f:"FOLDER_ENTRY",            # System folder
    0x2f:"VOLUME_NAME",
    0x41:"NETWORK_VOLUME_NAME",     # Windows Domain
    0x42:"NETWORK_VOLUME_NAME",     # Computer Name
    0x46:"NETWORK_VOLUME_NAME",     # MS Windows Network
    0x47:"NETWORK_VOLUME_NAME",     # Entire Network
    0xc3:"NETWORK_SHARE",           # Remote Share
    0x61:"URI",
    0x71:"CONTROL_PANEL",
    0x74:"UNKNOWN_74",              # System protected folder
}

FLAGS = {
    0x02:"has network volume name",
    0x80:"has unknown 16-bit value",
}

#####  Type overrides for output below #####

# http://msdn.microsoft.com/en-us/library/aa379358%28v=vs.85%29.aspx
# http://msdn.microsoft.com/en-us/library/cc248286%28v=prot.10%29.aspx
'''
'_GUID' : [ 0x10, {
    'Data1' : [ 0x0, ['unsigned long']],
    'Data2' : [ 0x4, ['unsigned short']],
    'Data3' : [ 0x6, ['unsigned short']],
    'Data4' : [ 0x8, ['array', 8, ['unsigned char']]],
'''

class _GUID(obj.CType):
    def __str__(self):
        return "{0:08x}-{1:04x}-{2:04x}-{3:02x}{4:02x}-{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}".format(self.Data1, self.Data2, self.Data3,
                self.Data4[0], self.Data4[1], self.Data4[2], self.Data4[3], self.Data4[4], self.Data4[5], self.Data4[6], self.Data4[7])

class ITEMPOS(obj.CType):
    def get_file_attrs(self):
        fileattrs = ""
        if self.Size >= 0x15:
            for f in FILE_ATTRS:
                if self.Attributes.FileAttrs & f == f:
                    fileattrs += FILE_ATTRS[f] + ", "
            fileattrs = fileattrs.rstrip(", ")
        return fileattrs

    def body(self, details):
        return "0|[{6}SHELLBAGS ITEMPOS] Name: {3}/Attrs: {4}/{5}|0|---------------|0|0|0|{0}|{1}|{2}|{2}\n".format(
            self.Attributes.AccessDate.v(), 
            self.Attributes.ModifiedDate.v(),
            self.Attributes.CreatedDate.v(),
            str(self.Attributes.UnicodeFilename), 
            self.get_file_attrs(), 
            details,
            self.obj_vm._config.MACHINE)

    def __str__(self):
        return "{0:<14} {1:30} {2:30} {3:30} {4:25} {5}".format(self.Attributes.FileName,
                str(self.Attributes.ModifiedDate),
                str(self.Attributes.CreatedDate),
                str(self.Attributes.AccessDate),
                self.get_file_attrs(),
                str(self.Attributes.UnicodeFilename))

    def get_items(self):
        items = {}
        items["FileName"] = str(self.Attributes.FileName)
        items["Modified"] = str(self.Attributes.ModifiedDate)
        items["Create"] = str(self.Attributes.CreatedDate)
        items["Access"] = str(self.Attributes.AccessDate)
        items["Attributes"] = self.get_file_attrs()
        items["Unicode"] = str(self.Attributes.UnicodeFilename)
        return items

    def get_header(self):
        return [("File Name", "14s"),
                ("Modified Date", "30"),
                ("Create Date", "30"),
                ("Access Date", "30"),
                ("File Attr", "25"),
                ("Unicode Name", ""),
               ]

class FILE_ENTRY(ITEMPOS):
    def get_file_attrs(self):
        fileattrs = ""
        for f in FILE_ATTRS:
            if self.Attributes.FileAttrs & f == f:
                fileattrs += FILE_ATTRS[f] + ", "
        fileattrs = fileattrs.rstrip(", ")
        return fileattrs

    def body(self, details):
        return "0|[{6}SHELLBAGS FILE_ENTRY] Name: {3}/Attrs: {4}/{5}|0|---------------|0|0|0|{0}|{1}|{2}|{2}\n".format(
            self.Attributes.AccessDate.v(), 
            self.Attributes.ModifiedDate.v(),
            self.Attributes.CreatedDate.v(),
            str(self.Attributes.UnicodeFilename),
            self.get_file_attrs(),
            details,
            self.obj_vm._config.MACHINE)

    def __str__(self):
        return "{0:<14} {1:30} {2:30} {3:30} {4:25}".format(self.Attributes.FileName,
                str(self.Attributes.ModifiedDate),
                str(self.Attributes.CreatedDate),
                str(self.Attributes.AccessDate),
                self.get_file_attrs())

    def get_items(self):
        items = {}
        items["FileName"] = str(self.Attributes.FileName)
        items["Modified"] = str(self.Attributes.ModifiedDate)
        items["Create"] = str(self.Attributes.CreatedDate)
        items["Access"] = str(self.Attributes.AccessDate)
        items["Attributes"] = self.get_file_attrs()
        return items

    def get_header(self):
        return [("File Name", "14s"),
                ("Modified Date", "30"),
                ("Create Date", "30"),
                ("Access Date", "30"),
                ("File Attr", "25"),
                ("Path", ""),
               ]

class FOLDER_ENTRY(obj.CType):
    def get_folders(self):
        folder_ids = ""
        for f in FOLDER_IDS:
            if self.Flags & f == f:
                folder_ids += FOLDER_IDS[f] + ", "
        folder_ids = folder_ids.rstrip(", ")
        return folder_ids

    def __str__(self):
        return "{0:<14} {1:40} {2:20} {3}".format("Folder Entry", 
               str(self.GUID),
               KNOWN_GUIDS.get(str(self.GUID), "Unknown GUID"),
               self.get_folders())

    def get_header(self):
        return [("Entry Type", "14s"),
                ("GUID", "40"),
                ("GUID Description", "20"),
                ("Folder IDs", ""),
               ]

class _VOLUSER_ASSIST_TYPES(obj.CType):
    def get_header(self):
        if hasattr(self, "Count") and hasattr(self, "FocusCount"):
            return [("Entry Type", "14s"),
                    ("Count", "5"),
                    ("Focus Count", "5"),
                    ("Time Focused", "20"),
                    ("Last Update", ""),
                   ]
        else:
            return [("Entry Type", "14s"),
                    ("ID", "10"),
                    ("Count", "10"),
                    ("Last Update", ""),
                   ]

    def __str__(self):
        if hasattr(self, "Count") and hasattr(self, "FocusCount"):
            return "{0:<14} {1:5} {2:5} {3:20} {4}".format("UserAssist",
                   self.Count,
                   self.FocusCount,
                   self.FocusTime,
                   self.LastUpdated)
        else:
            return "{0:<14} {1:5} {2:5} {3}".format("UserAssist",
                   self.ID,
                   self.CountStartingAtFive,
                   self.LastUpdated)

    def body(self, reg, key, subname, lastwrite):
        ID = "N/A"
        count = "N/A"
        fc = "N/A"
        tf = "N/A"
        if hasattr(self, "ID"):
            ID = "{0}".format(self.ID)
        if hasattr(self, "Count"):
            count = "{0}".format(self.Count)
        else:
            count = "{0}".format(self.CountStartingAtFive if self.CountStartingAtFive < 5 else self.CountStartingAtFive - 5)
        if hasattr(self, "FocusCount"):
            seconds = (self.FocusTime + 500) / 1000.0
            time = datetime.timedelta(seconds = seconds) if seconds > 0 else self.FocusTime
            fc = "{0}".format(self.FocusCount)
            tf = "{0}".format(time)

        subname = subname.replace("|", "%7c")

        return "0|[SHELLBAGS USERASSIST] Registry: {1}/Key: {7}/Value: {2}/LW: {8}/ID: {3}/Count: {4}/FocusCount: {5}/TimeFocused: {6}|0|---------------|0|0|0|{0}|{0}|{0}|{0}\n".format(
            self.LastUpdated.v(), reg, subname, ID, count, fc, tf, key, lastwrite)

class CONTROL_PANEL(FOLDER_ENTRY):
    def __str__(self):
        return "{0:<14} {1:40} {2:20} {3}".format("Control Panel",
               str(self.GUID),
               KNOWN_GUIDS.get(str(self.GUID), "Unknown GUID"),
               self.get_folders())

# taken from http://code.google.com/p/registrydecoder/source/browse/trunk/templates/template_files/ShellBagMRU.py#388
class UNKNOWN_00(FOLDER_ENTRY):
    def __str__(self):
        if self.DataSize == 0x1a:
            return "{0:<14} {1:40} {2:20} {3}".format("Folder",
               str(self.GUID),
               KNOWN_GUIDS.get(str(self.GUID), "Unknown GUID"),
               self.get_folders())
        #elif self.DataSize in [0xa4, 0xb4, 0x7a, 0xc4, 0x9a, 0x30]:
        # TODO: this is not clear yet
        #    return "{0:<14} {1:40} {2:20} {3}".format("Device Property",
        #       str(self.Name), "", "")
        # TODO: fix this for other types like "AugM" and 1SPS 
        else:
            return "{0:<14} {1:40} {2:20} {3}".format("Folder (unsupported)",
                "This property is not yet supported", "", "")

class VOLUME_NAME(obj.CType):
    def __str__(self):
        return "{0:14} {1}".format("Volume Name", self.Name)


    def get_header(self):
        return [("Entry Type", "14s"),
                ("Path", ""),
               ]

class NETWORK_VOLUME_NAME(obj.CType):
    def get_flags(self):
        flags = ""
        for f in FLAGS:
            if self.Flags & f == f:
                flags += FLAGS[f] + ", "
            flags = flags.rstrip(", ")
        return flags

    def __str__(self):
        return "{0:25} {1:20} {2} |".format("Network Volume Name", self.Description, self.Name)


    def get_header(self):
        return [("Entry Type", "25s"),
                ("Description", "20"),
                ("Name | Full Path", ""),
               ]


class NETWORK_SHARE(NETWORK_VOLUME_NAME):
    def __str__(self):
        return "{0:25} {1:20} {2}".format("Network Volume Share", self.Description, self.Name)


#####  End Type Overrides #####

        
class NullString(basic.String):
    def __str__(self):
        result = self.obj_vm.zread(self.obj_offset, self.length).split("\x00\x00")[0].replace("\x00", "")
        if not result:
            result = ""
        return result

    def v(self):
        result = self.obj_vm.zread(self.obj_offset, self.length).split("\x00\x00")[0].replace("\x00", "") 
        if not result:
            return obj.NoneObject("Cannot read string length {0} at {1:#x}".format(self.length, self.obj_offset))
        return result


shell_item_types = {
    'SHELLITEM': [ None, {
        'Size' : [ 0x0, ['unsigned short']],
        'Type' : [ 0x2, ['unsigned char']], # SHELL_ITEM_TYPES
    } ],
    'FOLDER_ENTRY': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x3, ['unsigned char']],  # FOLDER_IDS
        'GUID': [ 0x4, ['_GUID']],
    } ],
    'VOLUME_NAME': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Name': [ 0x3, ['String', dict(length = 22)]],
    } ],
    'NETWORK_VOLUME_NAME': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x4, ['unsigned char']],
        'Name': [ 0x5, ['String', dict(length = 255)]],
        'Description': [ lambda x: x.Name.obj_offset + len(x.Name), ['String', dict(length = 4096)]],
    } ],
    'URI': [ None, {
        'Flags': [ 0x3, ['unsigned char']],
        'UString': [ 0x8, ['String', dict(length = 4096)]],
        # other stuff here not filled in...
    } ],
    'CONTROL_PANEL': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x3, ['unsigned char']],
        'GUID': [ 0xe, ['_GUID']],
    } ],
    'NETWORK_SHARE': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x4, ['unsigned char']],
        'Name': [ 0x5, ['String', dict(length = 255)]], 
        'Description': [ lambda x: x.Name.obj_offset + len(x.Name), ['String', dict(length = 4096)]],
    } ],
    # These "OTHER" types are really not clear yet...
    'UNKNOWN_00': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x3, ['unsigned char']],
        'DataSize': [ 0x4, ['unsigned short']], #size of the following data
        'FolderAugM': [ 0x4, ['String', dict(length = 4)]],
        'PropertyList': [ 0xa, ['unsigned short']],
        'IdentifierSize': [ 0xc, ['unsigned short']],
        'GUID': [ 0xe, ['_GUID']],
        #'NameLength': [ 0x42, ['unsigned short']], # size of following data
        #'Name': [ 0x4a, ['String', dict(length = lambda x: x.NameLength * 2)]],
    } ],
    'UNKNOWN_01': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x3, ['unsigned char']],
        'Unknown': [ 0x4, ['unsigned int']],
    } ],
    'UNKNOWN_2E': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x3, ['unsigned char']],
        'GUID': [ 0x4, ['_GUID']],
    } ],
    'UNKNOWN_74': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']],
        'Flags': [ 0x3, ['unsigned char']],
        'Attributes' : [12, ['ATTRIBUTES']],
    } ],
}

itempos_types_XP = {
    'ATTRIBUTES': [ None, {
        'ModifiedDate': [ 0x0, ['DosDate', dict(is_utc = True)]], 
        'FileAttrs': [ 0x4, ['unsigned short']],
        'FileName': [ 0x6, ['String', dict(length = 255)]], # 8.3 File name although sometimes it's longer than 14 chars
        'FDataSize': [ lambda x: x.FileName.obj_offset + len(x.FileName) + (1 if len(x.FileName) % 2 == 1 else 2), ['unsigned short']],
        'EVersion': [ lambda x: x.FDataSize.obj_offset + 2, ['unsigned short']],
        'Unknown1': [ lambda x: x.EVersion.obj_offset + 2, ['unsigned short']],
        'Unknown2': [ lambda x: x.Unknown1.obj_offset + 2, ['unsigned short']], # 0xBEEF
        'CreatedDate': [ lambda x: x.Unknown2.obj_offset + 2, ['DosDate', dict(is_utc = True)]],
        'AccessDate': [ lambda x: x.CreatedDate.obj_offset + 4, ['DosDate', dict(is_utc = True)]],
        'Unknown3': [ lambda x: x.AccessDate.obj_offset + 4, ['unsigned int']],
        'UnicodeFilename': [ lambda x: x.Unknown3.obj_offset + 4, ['NullString', dict(length = 4096, encoding = 'utf8')]],
    } ],
    'ITEMPOS' : [ None, {
        'Size' : [ 0x0, ['unsigned short']],
        'Flags' : [ 0x2, ['unsigned short']],
        'FileSize' : [ 0x4, ['short']],
        'Attributes' : [ 0x8, ['ATTRIBUTES']],
    } ],
    'FILE_ENTRY': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']], # Type: 0x31, 0x32, 0xb1
        'Flags': [ 0x3, ['unsigned char']],
        'FileSize': [ 0x4, ['int']],
        'Attributes' : [ 0x8, ['ATTRIBUTES']],
    } ],
}

class ShellBagsTypesXP(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5}
    def modification(self, profile):
        profile.object_classes.update({
            'NullString': NullString,
            '_GUID':_GUID,
            'ITEMPOS':ITEMPOS,
            'FILE_ENTRY':FILE_ENTRY,
            'FOLDER_ENTRY':FOLDER_ENTRY,
            'CONTROL_PANEL':CONTROL_PANEL,
            'VOLUME_NAME':VOLUME_NAME,
            'NETWORK_VOLUME_NAME':NETWORK_VOLUME_NAME,
            'NETWORK_SHARE':NETWORK_SHARE,
            'UNKNOWN_00':UNKNOWN_00,
            '_VOLUSER_ASSIST_TYPES':_VOLUSER_ASSIST_TYPES,
        })
        profile.vtypes.update(shell_item_types)
        profile.vtypes.update(itempos_types_XP)


itempos_types_Vista = {
    'ATTRIBUTES' : [ None, {
        'ModifiedDate': [ 0x0, ['DosDate', dict(is_utc = True)]],
        'FileAttrs': [ 0x4, ['unsigned short']],
        'FileName': [ 0x6, ['String', dict(length = 255)]], 
        'FDataSize': [ lambda x: x.FileName.obj_offset + len(x.FileName) + (1 if len(x.FileName) % 2 == 1 else 2), ['unsigned short']],
        'EVersion': [ lambda x: x.FDataSize.obj_offset + 2, ['unsigned short']],
        'Unknown1': [ lambda x: x.EVersion.obj_offset + 2, ['unsigned short']],
        'Unknown2': [ lambda x: x.Unknown1.obj_offset + 2, ['unsigned short']], # 0xBEEF
        'CreatedDate': [ lambda x: x.Unknown2.obj_offset + 2, ['DosDate', dict(is_utc = True)]],
        'AccessDate': [ lambda x: x.CreatedDate.obj_offset + 4, ['DosDate', dict(is_utc = True)]],
        'Unknown3': [ lambda x: x.AccessDate.obj_offset + 4, ['unsigned int']],
        'FileReference': [ lambda x: x.Unknown3.obj_offset + 4, ['unsigned long long']], #MFT entry index 0-6, Sequence number 6-7
        'Unknown4': [ lambda x: x.FileReference.obj_offset + 8, ['unsigned long long']],
        'LongStringSize': [ lambda x: x.Unknown4.obj_offset + 8, ['unsigned short']],
        'UnicodeFilename': [ lambda x: x.LongStringSize.obj_offset + 2, ['NullString', dict(length = 4096, encoding = 'utf8')]],
        'AdditionalLongString': [ lambda x: x.UnicodeFilename.obj_offset + len(x.UnicodeFilename), ['NullString', dict(length = (lambda k: k.LongStringSize), encoding = 'utf8')]],
    } ], 
    'ITEMPOS' : [ None, {
        'Size' : [ 0x0, ['unsigned short']],
        'Flags' : [ 0x2, ['unsigned short']],
        'FileSize' : [ 0x4, ['short']],
        'Attributes' : [ 0x8, ['ATTRIBUTES']],
    } ],
    'FILE_ENTRY': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']], # Type: 0x31, 0x32, 0xb1
        'Flags': [ 0x3, ['unsigned char']],
        'FileSize': [ 0x4, ['int']],
        'Attributes' : [ 0x8, ['ATTRIBUTES']],
    } ],
}

class ShellBagsTypesVista(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6, 
                  'minor': lambda x: x == 0}
    def modification(self, profile):
        profile.object_classes.update({
            'NullString': NullString,
            '_GUID':_GUID,
            'ITEMPOS':ITEMPOS,
            'FILE_ENTRY':FILE_ENTRY,
            'FOLDER_ENTRY':FOLDER_ENTRY,
            'CONTROL_PANEL':CONTROL_PANEL,
            'VOLUME_NAME':VOLUME_NAME,
            'NETWORK_VOLUME_NAME':NETWORK_VOLUME_NAME,
            'NETWORK_SHARE':NETWORK_SHARE,
            'UNKNOWN_00':UNKNOWN_00,
            '_VOLUSER_ASSIST_TYPES':_VOLUSER_ASSIST_TYPES,
        })
        profile.vtypes.update(shell_item_types)
        profile.vtypes.update(itempos_types_Vista)


itempos_types_Win7 = {
    'ATTRIBUTES': [ None, {
        'ModifiedDate': [ 0x0, ['DosDate', dict(is_utc = True)]],
        'FileAttrs': [ 0x4, ['unsigned short']],
        'FileName': [ 0x6, ['String', dict(length = 255)]], 
        'FDataSize': [ lambda x: x.FileName.obj_offset + len(x.FileName) + (1 if len(x.FileName) % 2 == 1 else 2), ['unsigned short']],
        'EVersion': [ lambda x: x.FDataSize.obj_offset + 2, ['unsigned short']],
        'Unknown1': [ lambda x: x.EVersion.obj_offset + 2, ['unsigned short']],
        'Unknown2': [ lambda x: x.Unknown1.obj_offset + 2, ['unsigned short']], # 0xBEEF
        'CreatedDate': [ lambda x: x.Unknown2.obj_offset + 2, ['DosDate', dict(is_utc = True)]],
        'AccessDate': [ lambda x: x.CreatedDate.obj_offset + 4, ['DosDate', dict(is_utc = True)]],
        'Unknown3': [ lambda x: x.AccessDate.obj_offset + 4, ['unsigned int']],
        'FileReference': [ lambda x: x.Unknown3.obj_offset + 4, ['unsigned long long']], #MFT entry index 0-6, Sequence number 6-7
        'Unknown4': [ lambda x: x.FileReference.obj_offset + 8, ['unsigned long long']],
        'LongStringSize': [ lambda x: x.Unknown4.obj_offset + 8, ['unsigned short']],
        'Unknown5': [ lambda x: x.LongStringSize.obj_offset + 2, ['unsigned int']],
        'UnicodeFilename': [ lambda x: x.Unknown5.obj_offset + 4, ['NullString', dict(length = 4096, encoding = 'utf8')]],
        'AdditionalLongString': [ lambda x: x.UnicodeFilename.obj_offset + len(x.UnicodeFilename), ['NullString', dict(length = (lambda k: k.LongStringSize), encoding = 'utf8')]],
    } ],
    'ITEMPOS' : [ None, {
        'Size' : [ 0x0, ['unsigned short']],
        'Flags' : [ 0x2, ['unsigned short']],
        'FileSize' : [ 0x4, ['short']],
        'Attributes' : [ 0x8, ['ATTRIBUTES']],
    } ],
    'FILE_ENTRY': [ None, {
        'ShellItem': [ 0x0, ['SHELLITEM']], # Type: 0x31, 0x32, 0xb1
        'Flags': [ 0x3, ['unsigned char']],
        'FileSize': [ 0x4, ['int']],
        'Attributes' : [ 0x8, ['ATTRIBUTES']],
    } ],
}

class ShellBagsTypesWin7(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6, 
                  'minor': lambda x: x >= 1}
    def modification(self, profile):
        profile.object_classes.update({
            'NullString': NullString,
            '_GUID':_GUID,
            'ITEMPOS':ITEMPOS,
            'FILE_ENTRY':FILE_ENTRY,
            'FOLDER_ENTRY':FOLDER_ENTRY,
            'CONTROL_PANEL':CONTROL_PANEL,
            'VOLUME_NAME':VOLUME_NAME,
            'NETWORK_VOLUME_NAME':NETWORK_VOLUME_NAME,
            'NETWORK_SHARE':NETWORK_SHARE,
            'UNKNOWN_00':UNKNOWN_00,
            '_VOLUSER_ASSIST_TYPES':_VOLUSER_ASSIST_TYPES,
        })
        profile.vtypes.update(shell_item_types)
        profile.vtypes.update(itempos_types_Win7)



class ShellBags(common.AbstractWindowsCommand):
    """Prints ShellBags info"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("MACHINE", default = "",
                        help = "Machine name to add to timeline header")
        self.supported = ["FILE_ENTRY", "FOLDER_ENTRY", "CONTROL_PANEL", "VOLUME_NAME", "NETWORK_VOLUME_NAME", "NETWORK_SHARE", "UNKNOWN_00"]
        self.paths = {}

    def rreplace(self, s, old, new, occurrence):
        li = s.rsplit(old, occurrence)
        return new.join(li)

    def parse_key(self, regapi, reg, thekey, given_root = None):
        items = {} # a dictionary of shellbag objects indexed by value name
        for value, data in regapi.reg_yield_values(None, thekey, thetype = 'REG_BINARY', given_root = given_root):
            if data == None or thekey.find("S-") != -1 or str(value).startswith("LastKnownState") or thekey.lower().find("cmi-create") != -1:
                continue
            if str(value).startswith("ItemPos"):
                items[str(value)] = []
                bufferas = addrspace.BufferAddressSpace(self._config, data = data)
                i = 0x18
                while i < len(data) - 0x10:
                    item = obj.Object("ITEMPOS", offset = i, vm = bufferas)
                    if item != None and item.Size >= 0x15:
                        items[str(value)].append(item)
                    i += item.Size + 0x8
            elif str(value).lower().startswith("mrulistex"):
                list = {}
                bufferas = addrspace.BufferAddressSpace(self._config, data = data)
                i = 0
                while i < len(data) - 4:
                    list[obj.Object("int", offset = i, vm = bufferas).v()] = (i / 4)
                    i += 4
                items["MruListEx"] = list
            elif len(data) >= 0x10: 
                bufferas = addrspace.BufferAddressSpace(self._config, data = data)
                item = obj.Object("SHELLITEM", offset = 0, vm = bufferas)
                thetype = SHELL_ITEM_TYPES.get(int(item.Type), None)
                if thetype != None:
                    if thetype == "UNKNOWN_00" and len(data) == bufferas.profile.get_obj_size("_VOLUSER_ASSIST_TYPES"):
                        # this is UserAssist Data
                        item = obj.Object("_VOLUSER_ASSIST_TYPES", offset = 0, vm = bufferas)
                        try:
                            value = value.encode('rot_13')
                        except UnicodeDecodeError:
                            pass
                    else:
                        if bufferas.profile.get_obj_size(thetype) > len(data):
                            continue
                        item = obj.Object(thetype, offset = 0, vm = bufferas)
                    if hasattr(item, "DataSize") and item.DataSize <= 0:
                        continue
                    if thetype in self.supported:
                        temp = ""
                        if hasattr(item, "Attributes"):
                            temp = str(item.Attributes.UnicodeFilename)
                        elif hasattr(item, "Name"):
                            temp = str(item.Name)
                        self.paths[reg + ":" + thekey + ":" + str(value)] = temp
                        items[str(value)] = []
                        items[str(value)].append(item)
        return items 


    def calculate(self):
        addr_space = utils.load_as(self._config)
        version = (addr_space.profile.metadata.get('major', 0), 
                   addr_space.profile.metadata.get('minor', 0))
        
        if self._config.MACHINE != "":
            self._config.update("MACHINE", "{0} ".format(self._config.MACHINE))
        #set our current registry of interest and get its path
        regapi = registryapi.RegistryApi(self._config)
        regapi.reset_current()
        #scan for registries and populate them:
        print "Scanning for registries...."

        regapi.set_current('ntuser.dat')
        shellbag_data = []

        print "Gathering shellbag items and building path tree..."
        seen = {}
        for bk in BAG_KEYS:
            for cat, current_path in regapi.reg_yield_key("ntuser.dat", bk): 
                keys = [(k, bk + "\\" + k.Name) for k in regapi.reg_get_all_subkeys("ntuser.dat", key = None, given_root = cat)]
                for key, start in keys:
                    if key.Name:
                        if seen.get(start + "\\" + k.Name, None) != None:
                            continue
                        seen[start + "\\" + k.Name] = key.obj_offset
                        subkeys = [k for k in regapi.reg_get_all_subkeys("ntuser.dat", key = None, given_root = key)]
                        for k in subkeys:
                            keys.append((k, start + "\\" + k.Name))
                        items = self.parse_key(regapi, current_path, start, given_root = key)
                        if len(items) > 0:
                            shellbag_data.append((start, current_path, key, items))
        if version >= (6, 0):
            regapi.reset_current()
            regapi.set_current("UsrClass.dat")
            seen = {}
            for bk in USERDAT_KEYS:
                for cat, current_path in regapi.reg_yield_key("UsrClass.dat", bk): 
                    keys = [(k, bk + "\\" + k.Name) for k in regapi.reg_get_all_subkeys("UsrClass.dat", key = None, given_root = cat)]
                    for key, start in keys:
                        if key.Name:
                            if seen.get(start + "\\" + k.Name, None) != None:
                                continue
                            seen[start + "\\" + k.Name] = key.obj_offset
                            subkeys = [k for k in regapi.reg_get_all_subkeys("UsrClass.dat", key = None, given_root = key)]
                            for k in subkeys:
                                keys.append((k, start + "\\" + k.Name))
                            items = self.parse_key(regapi, current_path, start, given_root = key)
                            if len(items) > 0: 
                                shellbag_data.append((start, current_path, key, items))
        return shellbag_data

    def build_path(self, reg, key, item):
        path = ""
        if hasattr(item, "Attributes"):
            path = str(item.Attributes.UnicodeFilename)
        elif hasattr(item, "Name"):
            path = str(item.Name)
        else:
            return path
        while key != "": 
            parent = self.rreplace(key, "\\" + key.split("\\")[-1], "", 1)
            prev = self.paths.get(reg + ":" + parent + ":" + key.split("\\")[-1], "")
            if prev == "":
                break
            path = prev + "\\" + path
            key = parent
        return path
        

    def render_body(self, outfd, data):
        for name, reg, key, items in data:
            for item in items:
                if item == "MruListEx":
                    continue
                for shell in items[item]:
                    if type(shell) == ITEMPOS or type(shell) == FILE_ENTRY:
                        full_path = self.build_path(reg, name, shell).replace("\\\\", "\\")
                        outfd.write("{0}".format(shell.body("FullPath: {0}/Registry: {1}/Key: {2}/LW: {3}".format(full_path, reg, name, str(key.LastWriteTime)))))
                    elif type(shell) == _VOLUSER_ASSIST_TYPES:
                        outfd.write("{0}".format(shell.body(reg, name, item, str(key.LastWriteTime))))

    def unified_output(self, data):
        return TreeGrid([("Registry", str),
                       ("Key", str),
                       ("LastWrite", str),
                       ("FileName", str),
                       ("Create", str),
                       ("Access", str),
                       ("Attributes", str),
                       ("Unicode", str),
                       ("Path", str),
                       ],
                        self.generator(data))

    def generator(self, data):
        for name, reg, key, items in data:
            if not key:
                continue
            for item in items:
                if item == "MruListEx":
                    continue
                for shell in items[item]:
                    full_path = ""
                    if type(shell) == ITEMPOS or type(shell) == FILE_ENTRY:
                        full_path = self.build_path(reg, name, shell).replace("\\\\", "\\")
                        things = shell.get_items()
                        yield (0, [str(reg),
                            str(name),
                            str(key.LastWriteTime),
                            things.get("FileName", ""),
                            things.get("Create", ""),
                            things.get("Access", ""),
                            things.get("Attributes", ""),
                            things.get("Unicode", ""),
                            str(full_path)])

    def render_text(self, outfd, data):
        border = "*" * 75
        for name, reg, key, items in data:
            if not key: 
                continue
            first = True
            mru = items.get("MruListEx", None)
            mruheader = [("Value", "7"), ("Mru", "5")] if mru else [("Value", "25")]
            for item in items:
                if item == "MruListEx":
                    continue
                for shell in items[item]:
                    full_path = ""
                    if type(shell) != ITEMPOS and type(shell) != VOLUME_NAME:
                        full_path = self.build_path(reg, name, shell).replace("\\\\", "\\")
                    if first:
                        outfd.write(border + "\n")
                        outfd.write("Registry: " + reg + "\n")
                        outfd.write("Key: " + name + "\n")
                        outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                        curheader = shell.get_header()
                        self.table_header(outfd, mruheader + curheader)
                        first = False
                    if curheader != shell.get_header():
                        curheader = shell.get_header()
                        outfd.write("\n")
                        self.table_header(outfd, mruheader + curheader)
                    if mru:
                        outfd.write("{0:7} {1:<5} {2} {3}\n".format(item, mru[int(item)], str(shell), full_path))
                    else:
                        outfd.write("{0:25} {1} {2}\n".format(item, str(shell), full_path))
            if not first:
                outfd.write(border + "\n\n")


