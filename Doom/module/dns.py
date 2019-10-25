import subprocess
import logging
from impacket import LOG
from Doom.module import  logger
from Doom.module.color import C

class DNS(object):
    def __init__(self):
        self.target = ""
        self.zone = ""
        self.avaliable_opt = ["target","zone"]
        logger.init()

    def set_target(self, target):
        self.target = target
        print("TARGET => %s" % self.target)


    def set_zone(self, zonename):
        self.zone = zonename
        print("ZONE => %s" % self.zone)

    def show_options(self):
        print("\n\tShow Available options for current module\n")
        print("\tTARGET - REMOTE TARGET IP ADDRESS")
        print("\tZONE - BASE ZONE NAME TO USE AS TRANSFER (REQUIRED)")

        print("\n\tCurrent Settings\n")

        if self.target != "":
            print("\tTARGET - %s" % self.target)
        if self.zone != "":
            print("\tZONE - %s" % self.zone)

    def show_help(self):
        print("\n\tShow available commands for current module\n")
        print("\thelp - print this help")
        print("\tshow options - list available options")
        print("\tset - use to set required options\n")

    def run(self):
        '''
            Perform Dns Zone transfer on target server and target zone
        :return:
        '''
        try:
            if self.zone == "":
                raise Exception("Error Zone Name Require")
            LOG.info("Trying To Perform Zone Transfer on %s .." % self.target)
            output = subprocess.Popen(["dig","axfr","@%s" % self.target,"%s" % self.zone],stdout=subprocess.PIPE).communicate()[0]
            output = str(output,'UTF-8').split("\n")
            print(output)
            domains_list = []
            for string in output:
                if (".%s" % self.zone) in string:
                    domains_string = string
                    domains_string_list = domains_string.replace("\t"," ").split(" ")
                    for domain in domains_string_list:
                        if (".%s" % self.zone) in domain:
                            domains_list.append(domain)

            domains_list.append(self.zone+".")
            LOG.level = logging.DEBUG
            for domain in domains_list:
                LOG.debug(domain[:-1])
        except Exception as e:
            print(C.FAIL+C.BOLD+str(e)+C.ENDC)


