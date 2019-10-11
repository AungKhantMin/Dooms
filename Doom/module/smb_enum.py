from __future__ import division
from __future__ import print_function

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
            shell = MiniImpacketShell(smbClient)
            shares = shell.do_shares("shares")
            shares_list = []
            for i in range(len(shares)):
                share = shares[i]['shi1_netname'][:-1]
                if share not in self.ignore_share:
                    shares_list.append(share)

            logging.info("Listing Shares")
            logging.getLogger().level = logging.DEBUG
            for share in shares_list:
                    logging.debug(share)

            LOG.level = logging.INFO

            LOG.info("Listing File And Directory For Share %s " % share)
            for share in shares_list:
                shell.do_use(share)
                shell.do_ls('')

        except Exception as e:
            LOG.level = logging.DEBUG
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))

gg  = SMBEnum("10.10.10.14")
gg.tryLogin()
