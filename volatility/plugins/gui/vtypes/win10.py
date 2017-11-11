# Volatility
# Copyright (C) 2007-2017 Volatility Foundation
# Copyright (C) 2017 Michael Hale Ligh <michael.ligh@mnin.org>
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

import volatility.obj as obj 

class Win10x86_Gui(obj.ProfileModification):

    before = ["XP2003x86BaseVTypes", "Win32Kx86VTypes", "AtomTablex86Overlay", "Win32KCoreClasses", "Win8x86Gui"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4}

    def modification(self, profile):
        build = profile.metadata.get('build', 0)
    
        if build >= 15063:    
            profile.merge_overlay({
                'tagDESKTOP': [None, {
                    'rpdeskNext': [0x10, ['pointer', ['tagDESKTOP']]],
                    'rpwinstaParent': [0x14, ['pointer', ['tagWINDOWSTATION']]],
                    'pheapDesktop': [0x40, ['pointer', ['tagWIN32HEAP']]],
                    'PtiList': [0x5c, ['_LIST_ENTRY']],
                }],
                'tagTHREADINFO': [None, {
                    'ppi': [0xe0, ['pointer', ['tagPROCESSINFO']]],
                    'PtiLink': [0x188, ['_LIST_ENTRY']],
                }],
                'tagWND': [None, {
                    'spwndNext': [0x34, ['pointer', ['tagWND']]],
                    'spwndPrev': [0x38, ['pointer', ['tagWND']]],
                    'spwndParent': [0x3c, ['pointer', ['tagWND']]],
                    'spwndChild': [0x40, ['pointer', ['tagWND']]],
                    'lpfnWndProc': [0x68, ['pointer', ['void']]], #?
                    'pcls': [0x6c, ['pointer', ['tagCLS']]], #?
                    'strName': [0x8c, ['_LARGE_UNICODE_STRING']], #?
                }],
            })

class Win10x64_Gui(obj.ProfileModification):

    before = ["Win32KCoreClasses", "Win8x64Gui"]

    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4}

    def modification(self, profile):
        build = profile.metadata.get('build', 0)
    
        if build >= 15063:    
            profile.merge_overlay({
                'tagDESKTOP': [None, {
                    'rpdeskNext': [0x20, ['pointer64', ['tagDESKTOP']]],
                    'rpwinstaParent': [0x28, ['pointer64', ['tagWINDOWSTATION']]],
                    'pheapDesktop': [0x80, ['pointer', ['tagWIN32HEAP']]],
                    'PtiList': [0xA8, ['_LIST_ENTRY']],
                }],
                'tagTHREADINFO': [None, {
                    'ppi': [0x190, ['pointer', ['tagPROCESSINFO']]],
                     # zzzSetDesktop 
                     # mov [rbx+1B8h], rax
                     # lea rax, [rbx+2C8h]
                     # lea rcx, [rdi+0A8h] => int 29h 
                    'PtiLink': [0x2c8, ['_LIST_ENTRY']],
                }],
                'tagWND': [None, {
                    'spwndNext': [0x58, ['pointer64', ['tagWND']]],
                    'spwndPrev': [0x60, ['pointer64', ['tagWND']]],
                    'spwndParent': [0x68, ['pointer64', ['tagWND']]],
                    'spwndChild': [0x70, ['pointer64', ['tagWND']]],
                    'lpfnWndProc': [0xa0, ['pointer64', ['void']]],
                    'pcls': [0xa8, ['pointer64', ['tagCLS']]],
                    'strName': [0xe8, ['_LARGE_UNICODE_STRING']],
                }],
            })