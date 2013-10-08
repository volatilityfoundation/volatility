# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
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

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0
@contact:      jamie.levy@gmail.com
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

import volatility.plugins.registry.printkey as printkey
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.registry.hivelist as hivelist
import datetime

# for Windows 7 userassist info check out Didier Stevens' article
# from Into the Boxes issue 0x0: 
#  http://intotheboxes.wordpress.com/2010/01/01/into-the-boxes-issue-0x0/
ua_win7_vtypes = {
  '_VOLUSER_ASSIST_TYPES' : [ 0x48, {
    'Count': [0x04, ['unsigned int']],
    'FocusCount': [0x08, ['unsigned int']],
    'FocusTime': [0x0C, ['unsigned int']],
    'LastUpdated' : [0x3C, ['WinTimeStamp', dict(is_utc = True)]]
} ],
}

ua_vtypes = {
  '_VOLUSER_ASSIST_TYPES' : [ 0x10, {
    'ID': [0x0, ['unsigned int']],
    'CountStartingAtFive': [0x04, ['unsigned int']],
    'LastUpdated' : [0x08, ['WinTimeStamp', dict(is_utc = True)]]
} ],
}

class UserAssistVTypes(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x : x == 'windows'}
    def modification(self, profile):
        profile.vtypes.update(ua_vtypes)

class UserAssistWin7VTypes(obj.ProfileModification):
    before = ['UserAssistVTypes']
    conditions = {'os': lambda x : x == 'windows',
                  'major': lambda x : x == 6,
                  'minor': lambda x : x == 1}
    def modification(self, profile):
        profile.vtypes.update(ua_win7_vtypes)

# taken from http://msdn.microsoft.com/en-us/library/dd378457%28v=vs.85%29.aspx
folder_guids = {
    "{de61d971-5ebc-4f02-a3a9-6c82895e5c04}":"Add or Remove Programs (Control Panel)",
    "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}":"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "{a305ce99-f527-492b-8b1a-7e76fa98d6e4}":"Installed Updates",
    "{9E52AB10-F80D-49DF-ACB8-4330F5687855}":"%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn",
    "{df7266ac-9274-4867-8d55-3bd661de872d}":"Programs and Features",
    "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}":"%ALLUSERSPROFILE%\\OEM Links",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A4115719-D62E-491D-AA7C-E74B8BE3B067}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu",
    "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "{B94237E7-57AC-4347-9151-B08C6C32D1F7}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Templates",
    "{0AC0837C-BBF8-452A-850D-79D08E667CA7}":"(My) Computer",
    "{4bfefb45-347d-4006-a5be-ac0cb0567192}":"Conflicts",
    "{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}":"Network Connections",
    "{56784854-C6CB-462b-8169-88E350ACB882}":"%USERPROFILE%\\Contacts",
    "{82A74AEB-AEB4-465C-A014-D097EE346D63}":"Control Panel",
    "{2B0F765D-C0E9-4171-908E-08A611B84FF6}":"%APPDATA%\\Microsoft\\Windows\\Cookies",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}":"Desktop",
    "{5CE4A5E9-E4EB-479D-B89F-130C02886155}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\DeviceMetadataStore",
    "{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}":"%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms",
    "{374DE290-123F-4565-9164-39C4925E467B}":"%USERPROFILE%\\Downloads",
    "{1777F761-68AD-4D8A-87BD-30B759FA33DD}":"%USERPROFILE%\\Favorites",
    "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}":"%windir%\\Fonts",
    "{CAC52C1A-B53D-4edc-92D7-6B2E8AC19434}":"Games",
    "{054FAE61-4DD8-4787-80B6-090220C4B700}":"GameExplorer",
    "{D9DC8A3B-B784-432E-A781-5A1130A75963}":"%LOCALAPPDATA%\\Microsoft\\Windows\\History",
    "{52528A6B-B9E3-4ADD-B60D-588C2DBA842D}":"Homegroup",
    "{BCB5256F-79F6-4CEE-B725-DC34E402FD46}":"%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts",
    "{352481E8-33BE-4251-BA85-6007CAEDCF9D}":"%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files",
    "{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}":"The Internet",
    "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}":"%APPDATA%\\Microsoft\\Windows\\Libraries",
    "{bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968}":"%USERPROFILE%\\Links",
    "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}":"%LOCALAPPDATA% (%USERPROFILE%\\AppData\\Local)",
    "{A520A1A4-1780-4FF6-BD18-167343C5AF16}":"%USERPROFILE%\\AppData\\LocalLow",
    "{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}":"%windir%\\resources\\0409 (code page)",
    "{4BD8D571-6D19-48D3-BE97-422220080E43}":"%USERPROFILE%\\Music",
    "{2112AB0A-C86A-4FFE-A368-0DE96E47012E}":"%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms",
    "{C5ABBF53-E17F-4121-8900-86626FC2C973}":"%APPDATA%\\Microsoft\\Windows\\Network Shortcuts",
    "{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}":"Network",
    "{2C36C0AA-5812-4b87-BFD0-4CD0DFB19B39}":"%LOCALAPPDATA%\\Microsoft\\Windows Photo Gallery\\Original Images",
    "{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}":"%USERPROFILE%\\Pictures\\Slide Shows",
    "{A990AE9F-A03B-4E80-94BC-9912D7504104}":"%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms",
    "{33E28130-4E1E-4676-835A-98395C3BC3BB}":"%USERPROFILE%\\Pictures",
    "{DE92C1C7-837F-4F69-A3BB-86E631204A23}":"%USERPROFILE%\\Music\\Playlists",
    "{76FC4E2D-D6AD-4519-A663-37BD56068185}":"Printers",
    "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}":"%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts",
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}":"%USERPROFILE% (%SystemDrive%\\Users\\%USERNAME%)",
    "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}":"%ALLUSERSPROFILE% (%ProgramData%, %SystemDrive%\\ProgramData)",
    "{905e63b6-c1bf-494e-b29c-65b732d3d21a}":"%ProgramFiles%",
    "{6D809377-6AF0-444b-8957-A3773F02200E}":"%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}":"%ProgramFiles%",
    "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}":"%ProgramFiles%\\Common Files",
    "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}":"%ProgramFiles%\\Common Files",
    "{DE974D24-D9C6-4D3E-BF91-F4455120B917}":"%ProgramFiles%\\Common Files",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}":"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{DFDF76A2-C82A-4D63-906A-5644AC457385}":"%PUBLIC% (%SystemDrive%\\Users\\Public)",
    "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}":"%PUBLIC%\\Desktop",
    "{ED4824AF-DCE4-45A8-81E2-FC7965083634}":"%PUBLIC%\\Documents",
    "{3D644C9B-1FB8-4f30-9B45-F670235F79C0}":"%PUBLIC%\\Downloads",
    "{DEBF2536-E1A8-4c59-B6A2-414586476AEA}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\GameExplorer",
    "{48DAF80B-E6CF-4F4E-B800-0E69D84EE384}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Libraries",
    "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}":"%PUBLIC%\\Music",
    "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}":"%PUBLIC%\\Pictures",
    "{E555AB60-153B-4D17-9F04-A5FE99FC15EC}":"%ALLUSERSPROFILE%\\Microsoft\\Windows\\Ringtones",
    "{2400183A-6185-49FB-A2D8-4A392A602BA3}":"%PUBLIC%\\Videos",
    "{52a4f021-7b75-48a9-9f6b-4b87a210bc8f}":"%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch",
    "{AE50C081-EBD2-438A-8655-8A092E34987A}":"%APPDATA%\\Microsoft\\Windows\\Recent",
    "{1A6FDBA2-F42D-4358-A798-B74D745926C5}":"%PUBLIC%\\RecordedTV.library-ms",
    "{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}":"Recycle Bin",
    "{8AD10C31-2ADB-4296-A8F7-E4701232C972}":"%windir%\\Resources",
    "{C870044B-F49E-4126-A9C3-B52A1FF411E8}":"%LOCALAPPDATA%\\Microsoft\\Windows\\Ringtones",
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}":"%APPDATA% (%USERPROFILE%\\AppData\\Roaming)",
    "{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}":"%PUBLIC%\\Music\\Sample Music",
    "{C4900540-2379-4C75-844B-64E6FAF8716B}":"%PUBLIC%\\Pictures\\Sample Pictures",
    "{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}":"%PUBLIC%\\Music\\Sample Playlists",
    "{859EAD94-2E85-48AD-A71A-0969CB56A6CD}":"%PUBLIC%\\Videos\\Sample Videos",
    "{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}":"%USERPROFILE%\\Saved Games",
    "{7d1d3a04-debb-4115-95cf-2f29da2920da}":"%USERPROFILE%\\Searches",
    "{ee32e446-31ca-4aba-814f-a5ebd2fd6d5e}":"Offline Files",
    "{98ec0e18-2098-4d44-8644-66979315a281}":"Microsoft Office Outlook",
    "{190337d1-b8ca-4121-a639-6d472d16972a}":"Search Results",
    "{8983036C-27C0-404B-8F08-102D10DCFD74}":"%APPDATA%\\Microsoft\\Windows\\SendTo",
    "{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}":"%ProgramFiles%\\Windows Sidebar\\Gadgets",
    "{A75D362E-50FC-4fb7-AC2C-A8BEAA314493}":"%LOCALAPPDATA%\\Microsoft\\Windows Sidebar\\Gadgets",
    "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}":"%APPDATA%\\Microsoft\\Windows\\Start Menu",
    "{B97D20BB-F46A-4C97-BA10-5E3608430854}":"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "{43668BF8-C14E-49B2-97C9-747784D784B7}":"Sync Center",
    "{289a9a43-be44-4057-a41b-587a76d7e7f9}":"Sync Results",
    "{0F214138-B1D3-4a90-BBA9-27CBC0C5389A}":"Sync Setup",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}":"%windir%\\system32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}":"%windir%\\system32",
    "{A63293E8-664E-48DB-A079-DF759E0509F7}":"%APPDATA%\\Microsoft\\Windows\\Templates",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}":"%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    "{0762D272-C50A-4BB0-A382-697DCD729B80}":"%SystemDrive%\\Users",
    "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}":"%LOCALAPPDATA%\\Programs",
    "{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}":"%LOCALAPPDATA%\\Programs\\Common",
    "{f3ce0f7c-4901-4acc-8648-d5d44b04ef8f}":"The user's full name",
    "{A302545D-DEFF-464b-ABE8-61C8648D939B}":"Libraries",
    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}":"%USERPROFILE%\\Videos",
    "{491E922F-5643-4AF4-A7EB-4E7A138D8174}":"%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}":"%windir%",
}

class UserAssist(printkey.PrintKey, hivelist.HiveList):
    "Print userassist registry keys and information"

    def __init__(self, config, *args, **kwargs):
        printkey.PrintKey.__init__(self, config, *args, **kwargs)
        hivelist.HiveList.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'Hive offset (virtual)', type = 'int')

    def calculate(self):
        addr_space = utils.load_as(self._config)
        win7 = addr_space.profile.metadata.get('major', 0) == 6 and addr_space.profile.metadata.get('minor', 0) == 1

        if not self._config.HIVE_OFFSET:
            hive_offsets = [(self.hive_name(h), h.obj_offset) for h in hivelist.HiveList.calculate(self)]
        else:
            hive_offsets = [("User Specified", self._config.HIVE_OFFSET)]

        for name, hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
            else:
                skey = "software\\microsoft\\windows\\currentversion\\explorer\\userassist\\"
                if win7:
                    uakey = skey + "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count"
                    yield win7, name, rawreg.open_key(root, uakey.split('\\'))
                    uakey = skey + "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count"
                    yield win7, name, rawreg.open_key(root, uakey.split('\\'))
                else:
                    uakey = skey + "{75048700-EF1F-11D0-9888-006097DEACF9}\\Count"
                    yield win7, name, rawreg.open_key(root, uakey.split('\\'))
                    uakey = skey + "{5E6AB780-7743-11CF-A12B-00AA004AE837}\\Count"
                    yield win7, name, rawreg.open_key(root, uakey.split('\\'))

    def parse_data(self, dat_raw):
        bufferas = addrspace.BufferAddressSpace(self._config, data = dat_raw)
        uadata = obj.Object("_VOLUSER_ASSIST_TYPES", offset = 0, vm = bufferas)
        if len(dat_raw) < bufferas.profile.get_obj_size('_VOLUSER_ASSIST_TYPES') or uadata == None:
            return None

        output = ""
        if hasattr(uadata, "ID"):
            output = "\n{0:15} {1}".format("ID:", uadata.ID)
        if hasattr(uadata, "Count"):
            output += "\n{0:15} {1}".format("Count:", uadata.Count)
        else:
            output += "\n{0:15} {1}".format("Count:", uadata.CountStartingAtFive if uadata.CountStartingAtFive < 5 else uadata.CountStartingAtFive - 5)
        if hasattr(uadata, "FocusCount"):
            seconds = (uadata.FocusTime + 500) / 1000.0
            time = datetime.timedelta(seconds = seconds) if seconds > 0 else uadata.FocusTime
            output += "\n{0:15} {1}\n{2:15} {3}".format("Focus Count:", uadata.FocusCount, "Time Focused:", time)
        output += "\n{0:15} {1}\n".format("Last updated:", uadata.LastUpdated)

        return output

    def render_text(self, outfd, data):
        keyfound = False
        for win7, reg, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key name: {0}\n".format(key.Name))
                outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                outfd.write("\n")
                outfd.write("Subkeys:\n")
                for s in rawreg.subkeys(key):
                    if s.Name == None:
                        outfd.write("  Unknown subkey: " + s.Name.reason + "\n")
                    else:
                        outfd.write("  {0}\n".format(s.Name))
                outfd.write("\n")
                outfd.write("Values:\n")
                for v in rawreg.values(key):
                    tp, dat = rawreg.value_data(v)
                    subname = v.Name
                    if tp == 'REG_BINARY':
                        dat_raw = dat
                        dat = "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(dat)])
                        try:
                            subname = subname.encode('rot_13')
                        except UnicodeDecodeError:
                            pass
                        if win7:
                            guid = subname.split("\\")[0]
                            if guid in folder_guids:
                                subname = subname.replace(guid, folder_guids[guid])
                        d = self.parse_data(dat_raw)
                        if d != None:
                            dat = d + dat
                        else:
                            dat = "\n" + dat
                    #these types shouldn't be encountered, but are just left here in case:
                    if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                        dat = dat.encode("ascii", 'backslashreplace')
                    if tp == 'REG_MULTI_SZ':
                        for i in range(len(dat)):
                            dat[i] = dat[i].encode("ascii", 'backslashreplace')
                    outfd.write("\n{0:13} {1:15} : {2}\n".format(tp, subname, dat))
        if not keyfound:
            outfd.write("The requested key could not be found in the hive(s) searched\n")
