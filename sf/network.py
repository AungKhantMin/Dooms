import subprocess,multiprocessing,os
from ipaddress import ip_network

def RES(ip: str):
    '''
        To Use With Filter. Use to remove Empty String
    '''
    if ip == '':
        return False
    else:
        return True


def generateIP(network : str, subnet: str):
    '''
        Generate Ip address from subnets
    '''
    ipV4Obj =  list(ip_network(network+'/'+subnet).hosts())
    ips = []
    for x in ipV4Obj:
        ips.append(str(x))
    return ips

def pingsweepNetwork(network : str,subnet: str = '24' ):
    '''
        Ping Sweep scan. Scan for active hosts in network.
    '''
    ips = generateIP(network,subnet)
    p = multiprocessing.Pool(len(ips))
    activeIP = list(filter(RES,p.map(pingsweep,ips)))
    print(activeIP)
            

def pingsweep(ip : str):
    '''
        Ping Sweep Scan For Single Machine
    '''
    activeIP = ""
    devnull = open(os.devnull,'w')
    try: 
        subprocess.check_call(['ping','-c','1',ip],stdout=devnull)
        activeIP = ip
    except:
        pass
    return activeIP

pingsweepNetwork('192.168.43.0','24')