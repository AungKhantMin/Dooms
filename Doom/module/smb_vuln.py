import os
import subprocess
from pymetasploit3.msfrpc import MsfRpcClient
from time import  sleep
import logging
from Doom.module import logger
from impacket import LOG
from Doom.module.color import C

class SMB_VULN(object):
    def __init__(self,password=""):
        logger.init()
        self.password = password
        try:
            self.client = MsfRpcClient(self.password,port=55553)
            self.cid = self.client.consoles.console().cid
            self.console = self.client.consoles.console(self.cid)
        except Exception as e:
            LOG.level = logging.CRITICAL
            logging.critical(C.FAIL +str(e) + C.ENDC)

    def set_target(self, ip):
        self.target = ip
        print("TARGET => %s" % self.target)

    def show_options(self):
        print("\n\tShow Available options for current module\n")
        print("\tTARGET - REMOTE TARGET IP ADDRESS")

        print("\n\tCurrent Settings\n")

        if self.target != "":
            print("\tTARGET - %s" % self.target)

    def show_help(self):
        print("\n\tShow available commands for current module\n")
        print("\thelp - print this help")
        print("\tshow options - list available options")
        print("\tset - use to set required options\n")

    def run(self,target):
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

