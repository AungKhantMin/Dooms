from Doom.module.network import *


n = Network()
hosts = n.pingsweepNetwork('192.168.1.0','24')
for host in hosts:
    ports = n.multiPortScan(host,n.commonPort)
    portStr = ','.join(ports)
    n.nmapScan(host,ports)
