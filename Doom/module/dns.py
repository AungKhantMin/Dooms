import subprocess
import logging
from impacket import LOG
from Doom.module import  logger


class DNS(object):
    def __init__(self,ip,zonename):
        self.target = ip
        self.zone = zonename
        logger.init()

    def setTarget(self, target):
        self.target = target

    def setZone(self, zonename):
        self.zone = zonename

    def zoneTransfer(self):
        '''
            Perform Dns Zone transfer on target server and target zone
        :return:
        '''
        LOG.info("Trying To Perform Zone Transfer on %s .." % self.target)
        output = subprocess.Popen(["dig","axfr","@%s" % self.target,"%s" % self.zone],stdout=subprocess.PIPE).communicate()[0]
        output = str(output,'UTF-8').split("\n")
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



dns = DNS("10.10.10.123","friendzone.red")

dns.zoneTransfer()
