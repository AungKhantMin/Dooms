from lib.network import *
import argparse


if __name__ == '__main__':
    try:
        n = Network()
        x = n.pingsweepNetwork('192.168.43.0')
        print(x)
        for host in x:
            port = n.portScan(host,n.commonPort)
            print(port)
            print(n.nmapScan(host,port))
    except KeyboardInterrupt:
        exit(0)
    except:
        pass