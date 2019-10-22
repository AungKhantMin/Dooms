from Doom.module.ftplib import FTP
from impacket import LOG
from Doom.module import logger
import logging
from Doom.module.color import C

class FTP_ENUM(object):
    def __init__(self,port=21,user="anonymous",passowrd="anonymous@"):
        self.target = ""
        self.port = port
        self.user = user
        self.password = passowrd
        self.avaliable_opt = ["target","port" ,"user" ,"password" ]
        logger.init()
        self.ftp = FTP(self.target)

    def set_target(self, ip):
        self.target = ip
        print("TARGET => %s" % self.target)

    def set_port(self, port):
        self.port = port
        print("PORT => %s" % self.port)

    def set_user(self,user):
        self.user = user
        print("USER => %s" % self.user)

    def set_password(self,password):
        self.password = password
        print("PASSWORD => %s" % self.password)

    def show_help(self):
        print("\n\tShow available commands for current module\n")
        print("\tshow help - print this help")
        print("\tshow options - list available options")
        print("\tset - use to set required options\n")

    def show_options(self):
        print("\n\tShow Available options for current module\n")
        print("\tTARGET - REMOTE TARGET IP ADDRESS")
        print("\tUSER - USER NAME USE TO AUTHENTICATE TO REMOTE SERVER (OPTIONAL)")
        print("\tPASSWORD - PASSWORD  USE TO AUTHENTICATE TO REMOTE SERVER (OPTIONAL)\n")
        print("\tPORT - TARGET PORT RUNNING FTP SERVICE")

        print("\n\tCurrent Settings\n")

        if self.target != "":
            print("\tTARGET - %s" % self.target)
        if self.user != "Guest":
            print("\tUSER - %s" % self.user)
        if self.password != "":
            print("\tPASSWORD - %s" % self.password)
        if self.port is not None:
            print("\tPORT - %d\n" % self.port)


    def tryLogin(self):
        try:
            LOG.info("Trying To Login With User %s .." % self.user)
            output = self.ftp.login(user=self.user,passwd=self.password)
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


    def run(self):
        try:
            self.tryLogin()
            self.listDirectoryRescursive()
        except Exception as e:
            print(C.FAIL+C.BOLD+'[-] ' +str(e)+C.ENDC)
