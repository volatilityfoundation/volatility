""" This Address Space allows us to open ewf files """

has_pyewf = False
try:
    import pyewf
    has_pyewf = True
except ImportError:
    pass

import volatility.plugins.addrspaces.standard as standard

if has_pyewf:

    class EWFPyAddressSpace(standard.FileAddressSpace):
        """ An EWF capable address space. """
        order = 20
        def __init__(self, base, config, **kwargs):
            standard.FileAddressSpace.__init__(self, base, config, layered = False)
            self.as_assert(pyewf.check_file_signature(self.fname), "EWF signature not present")
            self.fhandle = pyewf.new_handle()
            self.fhandle.open([self.fname], pyewf.get_flags_read())
            self.fhandle.seek(0, 2)
            self.fsize = self.fhandle.tell()
            self.fhandle.seek(0)

        ### Potentially we can drop this when unnecessary
        def write(self, _addr, _buf):
            """ Never allow writing to an EWF file """
            if not self._config.WRITE:
                return False
            raise NotImplementedError("Write support is not yet implemented for EWF files")

        def read(self, offset, length):
            print "Reading offset", hex(offset), "length", length
            return standard.FileAddressSpace.read(self, offset, length)
