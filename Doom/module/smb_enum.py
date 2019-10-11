from __future__ import division
from __future__ import print_function

import re
import logging
from Doom.module import logger
from Doom.module.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection
from impacket import  LOG


class SMBEnum(object):
    def __init__(self,ip):
        self.target = ip
        self.port = 445
        self.user = "Guest"
        self.password = ""
        self.ignore_share = ["IPC$"]
        logger.init()



    def tryLogin(self):
        try:
            logging.info("Trying To Authenticate As %s ..." % self.user)
            smbClient = SMBConnection(self.target,self.target,sess_port=self.port)
            smbClient.login(self.user,self.password)
            logging.info("Successfully Login As %s ..." % self.user)
            self.shell = MiniImpacketShell(smbClient)
            shares = self.shell.do_shares("shares")
            shares_list = []

            logging.info("Listing Shares")
            logging.getLogger().level = logging.DEBUG

            for i in range(len(shares)):
                share = shares[i]['shi1_netname'][:-1]
                logging.debug(share)
                if share not in self.ignore_share:
                    if "$" not in share:
                        shares_list.append(share)

            LOG.level = logging.INFO
            for share in shares_list:
                LOG.info("Listing File And Directory For Share %s \n" % share)
                self.shell.do_use(share)
                directory_list = self.shell.do_ls('')
                print("\n")
                self.recursive_dirlist(directory_list,share)

        except Exception as e:
            LOG.level = logging.DEBUG
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))

    def recursive_dirlist(self,directory_list,share=""):

            if directory_list is not None:
                for directory in directory_list:
                    LOG.info("Listing File And Directory For Path \\\\%s\\%s" % (share, directory))
                    print("\n")
                    self.shell.do_cd(directory)
                    directory_list = self.shell.do_ls('')
                    print("\n")
                    temp_share = share
                    if len(directory_list) != 0 :
                        share += "\\" +directory
                        self.recursive_dirlist(directory_list,share)
                    else:
                        self.shell.do_cd("..")
                        share = temp_share



gg  = SMBEnum("10.10.10.134")
gg.tryLogin()
