"""
@author:       Slavi Parpulev
"""
import re
import base64
import volatility.plugins.common as common 
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.taskmods as taskmods

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

signatures = {
    'namespace1' : 'rule pivars {strings: $command = { \
        70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d\
        4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64\
        64 65 6e 20 2d 45 6e 63 20}\
        condition: $command}'
}

# signatures = {
#     'namespace1' : 'rule pivars {strings: $a = /powershell.exe.-NoP.-NonI.-W.Hidden.-Enc.([a-zA-Z0-9]+)/ condition: $a}'
# }


class PSEmpire(taskmods.DllList):
    """A plugin detecting the presence of PowerShell Empire. Idally run against a PID of powershell.exe"""


    def get_vad_base(self, task, address):
        """ Get the VAD starting address """        

        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start

        # This should never really happen
        return None

    def calculate(self):
        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)
        
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
	    # For each process in the list
        for task in self.filter_tasks(tasks.pslist(addr_space)):
            # print task.ImageFileName
            for vad, address_space in task.get_vads(vad_filter = task._injection_filter):
				# Injected code detected if there's values returned
                rules = yara.compile(sources = signatures)
                scanner = malfind.VadYaraScanner(task = task, rules = rules)
                # print 'before'
                for hit, address in scanner.scan():
            	    vad_base_addr = self.get_vad_base(task, address)
            	    
            	    # Get a chuck of memory of size 2048 next to where the string was detected
                    content = address_space.zread(address, 2048)
                    yield task, address, vad_base_addr, content
                    break
                # break  # Show only 1 instance of detected injection per process

    def render_text(self, outfd, data):
        for task, address, vad_base_addr, content in data:
            finalstring = []
            # hex dump returns 16 bytes at a time, walk the entire dump and get all values in finalstring
            for offset,h,c in utils.Hexdump(content):
                finalstring.append(''.join(c))
            # Get only the base64 part of the string and decode utf16 otherwise next regex fails to interpret the value as ascii
            obfuscated = base64.b64decode(re.findall(r'.+-Enc\.([a-zA-Z0-9]+)', "".join(finalstring))[0]).decode('utf16')
            # Get server value and port from the string
            try:
                server = re.findall(r'http.+//(.+):', obfuscated)[0]
            except:
                server = "Not detected"
            try:
                port = re.findall(r'http.+:(.+)/', obfuscated)[0]
            except:
                port = "Not found"

            outfd.write("Process: {0} Pid: {1} Vad_base: {2:#x} Detected at Address: {3:#x}\n".format(
                task.ImageFileName, task.UniqueProcessId, vad_base_addr, address))

            outfd.write("Connecting to - Server: {0} Port: {1}\n".format(
                server, port))

            outfd.write("{0}\n".format("\n".join(
                ["{0:#010x}  {1:<48}  {2}".format(address + o, h, ''.join(c))
                for o, h, c in utils.Hexdump(content[:64])
                ])))
