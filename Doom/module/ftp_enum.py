from Doom.module.ftplib import FTP
from impacket import LOG
from Doom.module import logger
import logging

class FTPEnum(object):
    def __init__(self,ip,port=21,user="anonymous",passowrd="anonymous@"):
        self.target = ip
        self.port = port
        logger.init()
        self.ftp = FTP(self.target)

    def setTarget(self, ip):
        self.target = ip

    def setPort(self, port):
        self.port

    def tryLogin(self,user="anonymous",password="anonymous@"):
        try:
            LOG.info("Trying To Login With User %s .." %user)
            output = self.ftp.login()
            LOG.info(output)
            self.listDirectoryRescursive()
        except Exception as e:
            LOG.level = logging.CRITICAL
            LOG.critical(str(e))


    def listDirectoryRescursive(self,path="/"):
        output = self.ftp.retrlines("LIST")
        directory_list = []
        file_list =[]
        for x in output:
            list = x.split(' ')
            if "<DIR>" in list or "d-" in list[0] or "dr" in list[0]:
                directory_list.append(list[-1])
            else:
                file_list.append(list[-1])

        LOG.info("Listing Directory and File For %s" % path)
        LOG.level = logging.DEBUG
        for directory in directory_list:
            LOG.debug(directory)
        for file in file_list:
            LOG.debug(file)

        directory_list.append("")
        if len(directory_list) != 0:
            for directory in directory_list:
                try:
                    if directory == "":
                        self.ftp.cwd("..")
                    else :
                        self.ftp.cwd(directory)
                        self.listDirectoryRescursive(self.ftp.pwd())

                except Exception as e:
                    LOG.level = logging.CRITICAL
                    LOG.critical(str(e)[:-1] + " "+ path+"/"+directory)

        else:
            self.ftp.cwd("..")


    def listFile(self):
        pass
