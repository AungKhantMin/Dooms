import logging
import subprocess
import threading

from Doom.module import logger
from impacket import LOG


class Nikto(object):
    def __init__(self, ip, portNum):
        self.target = ip


    def niktoScan(self):
        output = \
            subprocess.Popen(["nikto.pl", "-h", "portNum"], stdout=subprocess.PIPE).communicate()[0]
        return output


        vulnerability = []


        return vulnerability
