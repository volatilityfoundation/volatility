import volatility.plugins.common as common
import volatility.utils as utils
import volatility.plugins.filescan as filescan
import volatility.plugins.modscan as modscan
import volatility.plugins.gui.atoms as atoms
import volatility.plugins.gui.windowstations as windowstations
import volatility.plugins.sockscan as sockscan
import volatility.plugins.connscan as connscan
import volatility.plugins.netscan as netscan
import volatility.plugins.malware.callbacks as callbacks

class MultiScan(common.AbstractScanCommand):
    """Scan for various objects at once"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractScanCommand.__init__(self, config, *args, **kwargs)

        self.scanners = [
            filescan.PoolScanFile,
            filescan.PoolScanDriver,
            filescan.PoolScanSymlink,
            filescan.PoolScanMutant,
            filescan.PoolScanProcess,
            modscan.PoolScanModule,
            modscan.PoolScanThread,
            atoms.PoolScanAtom,
            windowstations.PoolScanWind,
            ]

    def calculate(self):
        addr_space = utils.load_as(self._config)

        version = (addr_space.profile.metadata.get("major", 0), 
                   addr_space.profile.metadata.get("minor", 0))

        if version < (6, 0):
            self.scanners.append(sockscan.PoolScanSocket)
            self.scanners.append(connscan.PoolScanConn)
        else:
            self.scanners.append(netscan.PoolScanUdpEndpoint)
            self.scanners.append(netscan.PoolScanTcpListener)
            self.scanners.append(netscan.PoolScanTcpEndpoint)
            self.scanners.append(callbacks.PoolScanDbgPrintCallback)
            self.scanners.append(callbacks.PoolScanRegistryCallback)
            self.scanners.append(callbacks.PoolScanPnp9)
            self.scanners.append(callbacks.PoolScanPnpD)
            self.scanners.append(callbacks.PoolScanPnpC)

        self.scanners.append(callbacks.PoolScanFSCallback)
        self.scanners.append(callbacks.PoolScanShutdownCallback)
        self.scanners.append(callbacks.PoolScanGenericCallback)


        for objct in self.scan_results(addr_space):
            yield objct

    def render_text(self, outfd, data):
        for objct in data:
            print objct