from ftplib import FTP
from impacket import LOG
from Doom.module import logger
import logging

class FTPEnum(object):
    def __init__(self,ip,port=21):
        self.target = ip
        self.port = port

    def tryLogin(self,user="anonymous",password="anonymous@"):
        try:
            self.ftp = FTP(self.target)
            self.ftp.login()
        except Exception as e:
            LOG.level = logging.CRITICAL
            LOG.critical(str(e))



ftp = FTPEnum('10.10.10.139')

ftp.tryLogin()
