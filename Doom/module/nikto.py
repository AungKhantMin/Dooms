import logging
import subprocess
import threading

from Doom.module import logger
from impacket import LOG


class Nikto(object):
    def __init__(self, ip, port="80"): # This is assigning the default param
        self.target = ip
        self.port = port

    def niktoScan(self):
        output = \
            subprocess.Popen(["nikto.pl", "-h", self.target, "-p" , self.port], stdout=subprocess.PIPE).communicate()[0]
        return output


        vulnerability = []


        return vulnerability
