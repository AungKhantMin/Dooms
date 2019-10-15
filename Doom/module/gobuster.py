import os
import subprocess
import logging
from impacket import LOG
from Doom.module import logger



class GoBuster(object):
    '''
    Run Directory BruteForcing Against Web Server using dirb small-medium  as wordlist and gobuster
    '''
    def __init__(self,ip,port=80,wordlist="../wordlist/directory-list-2.3-medium.txt",thread=50):
        self.target = ip
        self.port = port
        self.wordlist = wordlist
        self.thread = thread
        logger.init()

    def setTarget(self, ip):
        self.target = ip

    def setPort(self, port):
        self.port = port

    def setThread(self, thread):
        self.thread = thread

    def run(self):
        LOG.info("Running Gobuster Against The Server ..")
        # os.system("gobuster  dir -t 50 -w %s --url %s:%s" % (self.wordlist,self.target,self.port))
        output = subprocess.Popen(["gobuster", "dir", "-t", "%d" % self.thread, "-w", "%s" % self.wordlist, "--url",
                                   "%s:%s" % (self.target, self.port)]
                                  , stdout=subprocess.PIPE).communicate()[0]
        raw_list = str(output, 'UTF-8').split('\n')
        directory_list = []
        for raw in raw_list:
            if "Status: 301" in raw or "Status: 200" in raw or "Status: 403" in raw:
                directory_list.append(raw)
        if len(directory_list) != 0:
            for directory in directory_list:
                LOG.level = logging.DEBUG
                LOG.debug(directory)
        else:
            LOG.info("BadLuck No Directory Found. Try Another Wordlist ...")


go = GoBuster('10.10.10.146', wordlist="../wordlist/common.txt", port=443)

go.run()
