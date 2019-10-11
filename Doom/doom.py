import sys
from module.nmap import Nmap
from module.smb_vuln import *

def doom():
    open_port = Nmap.multiPortScan(sys.argv[1])
    nmap_result = Nmap.defaultScan()
    if 455 in open_port:
        # call SMB related module
        pass

    if 80 or 443 in open_port:
        # call Web related module
        pass

    if 21 in open_port:
        # call FTP Service Module
        pass
