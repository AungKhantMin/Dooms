import os
import subprocess
from pymetasploit3.msfrpc import MsfRpcClient
from time import  sleep
import logging
from Doom.module import logger
from impacket import LOG

class SMBVulnScan():
    def __init__(self,password):
        self.password = password
        self.client = MsfRpcClient(self.password,port=55553)
        self.cid = self.client.consoles.console().cid
        self.console = self.client.consoles.console(self.cid)
        logger.init()

    def check_ms17_010(self,target):
        LOG.info("Checking If Server is Vulnerable to MS17_010")
        self.console.write("use auxiliary/scanner/smb/smb_ms17_010")
        self.console.write("set RHOSTS 10.10.10.134")
        self.console.read()
        self.console.write('run')
        data = ''

        while data == '' or self.console.is_busy():
            sleep(1)
            data += self.console.read()['data']

        print(data)
        if "NOT" not in data:
            LOG.info("You can use MS17-010 to exploit the target machine")

gg = SMBVulnScan("D4rkn3ss")
gg.check_ms17_010("10.10.10.134")
