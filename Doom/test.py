from Doom.module.network import *


n = Network()
# hosts = n.pingsweepNetwork('192.168.1.0','24')
# for host in hosts:
#     ports = n.multiPortScan(host,n.commonPort)
#     portStr = ','.join(ports)
#     print(portStr)
print(n.nmapScan('192.168.1.1',['53','80','443']))

#lol
