import os
import subprocess
import logging
from impacket import LOG
from Doom.module import logger
from Doom.module.color import C


class GOBUSTER(object):
    '''
    Run Directory BruteForcing Against Web Server using dirb small-medium  as wordlist and gobuster
    '''
    def __init__(self,port=80,wordlist="wordlist/directory-list-2.3-medium.txt",thread=50):
        self.target = ""
        self.port = port
        self.wordlist = wordlist
        self.thread = thread
        self.avaliable_opt = ["target","port","thread","wordlist"]
        logger.init()

    def set_wordlist(self,wordlist):
        self.wordlist = wordlist
        print("WORDLIST => %s" % self.wordlist)

    def set_target(self, ip):
        self.target = ip
        print("TARGET => %s" % self.target)

    def set_port(self, port):
        self.port = port
        print("PORT => %d" % self.port)

    def set_thread(self, thread):
        self.thread = thread
        print("THREAD => %d" % self.thread)

    def show_help(self):
        print("\n\tShow available commands for current module\n")
        print("\thelp - print this help")
        print("\tshow options - list available options")
        print("\tset - use to set required options\n")


    def show_options(self):
        print("\n\tShow Available options for current module\n")
        print("\tTARGET - REMOTE TARGET IP ADDRESS")
        print("\tWORDLIST - WORDLIST TO USE AGAINST SERVER (OPTIONAL) ")
        print("\tPORT - THE PORT THAT WEBSERVICE IS RUNNING ON\n")
        print("\tTHREAD - NUMBER OF THREADS")
        print("\n\tCurrent Settings\n")

        if self.target != "":
            print("\tTARGET - %s" % self.target)
        if self.wordlist != "Guest":
            print("\tWORDLIST - %s" % self.wordlist)
        if self.thread != "":
            print("\tTHREAD - %s" % self.thread)
        if self.port != "":
            print("\tPORT - %s" % self.port)

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

