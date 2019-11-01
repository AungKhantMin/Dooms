#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCE/RPC and SMB.

import sys
import os
import cmd
import logging
from threading import Thread, Lock
import argparse
import random
import string
import time
from six import PY3

from impacket.examples import logger
from impacket import version, smb
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall
from Doom.module.color import C

class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT         = "RemCom_stdout"
RemComSTDIN          = "RemCom_stdin"
RemComSTDERR         = "RemCom_stderr"

lock = Lock()

class PSEXEC:
    def __init__(self, command="cmd.exe", path=None, exeFile=None, copyFile=None, port=445,
                 username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, serviceName=''):
        self.username = username
        self.password = password
        self.port = port
        self.command = command
        self.path = path
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.exeFile = exeFile
        self.copyFile = copyFile
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        self.serviceName = serviceName
        self.target = None
        logging.getLogger().level = logging.DEBUG
        self.avaliable_opt = ['target','user','password','port','hashes','aeskey','mode','share','kerberos','dcip','domain']

        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def exec(self):
        remoteName = remoteHost = self.target
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.port)
        rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash,
                                         self.nthash, self.aesKey)

        rpctransport.set_kerberos(self.doKerberos, self.kdcHost)
        self.doStuff(rpctransport)

    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid,pipe)
                pipeReady = True
            except:
                tries -= 1
                time.sleep(2)
                pass

        if tries == 0:
            raise Exception('Pipe not ready, aborting')

        fid = s.openFile(tid,pipe,accessMask, creationOption = 0x40, fileAttributes = 0x80)

        return fid

    def doStuff(self, rpctransport):

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()

        try:
            unInstalled = False
            s = rpctransport.get_smb_connection()

            # We don't wanna deal with timeouts from now on.
            s.setTimeout(100000)
            if self.exeFile is None:
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), remcomsvc.RemComSvc(), self.serviceName)
            else:
                try:
                    f = open(self.exeFile)
                except Exception as e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), f)

            if installService.install() is False:
                return

            if self.exeFile is not None:
                f.close()

            # Check if we need to copy a file for execution
            if self.copyFile is not None:
                installService.copy_file(self.copyFile, installService.getShare(), os.path.basename(self.copyFile))
                # And we change the command to be executed to this filename
                self.command = os.path.basename(self.copyFile) + ' ' + self.command

            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s,tid,r'\RemCom_communicaton',0x12019f)

            packet = RemComMessage()
            pid = os.getpid()

            packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
            if self.path is not None:
                packet['WorkingDir'] = self.path
            packet['Command'] = self.command
            packet['ProcessID'] = pid

            s.writeNamedPipe(tid, fid_main, packet.getData())

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe = RemoteStdInPipe(rpctransport,
                                         r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
                                         smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare())
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stderr_pipe.start()

            # And we stay here till the end
            ans = s.readNamedPipe(tid,fid_main,8)

            if len(ans):
                retCode = RemComResponse(ans)
                logging.info("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (
                self.command, retCode['ErrorCode'], retCode['ReturnCode']))
            installService.uninstall()
            if self.copyFile is not None:
                # We copied a file for execution, let's remove it
                s.deleteFile(installService.getShare(), os.path.basename(self.copyFile))
            unInstalled = True
            sys.exit(retCode['ErrorCode'])

        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.debug(str(e))
            if unInstalled is False:
                installService.uninstall()
                if self.copyFile is not None:
                    s.deleteFile(installService.getShare(), os.path.basename(self.copyFile))
            sys.stdout.flush()
            sys.exit(1)

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


    def set_kerberos(self,k):
        if "true" == str.lower(k):
            self.doKerberos = True
        else:
            self.doKerberos = False
        print("KERBEROS => %s" % k)


    def show_options(self):
        print("\n\tShow Available options for current module\n")
        print("\tTARGET - REMOTE TARGET IP ADDRESS")
        print("\tUSER - USERNAME USE TO AUTHENTICATE TO REMOTE SERVER ")
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


class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            #self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
            self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.class__)


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    global LastDataSent
                    if ans != LastDataSent:
                        sys.stdout.write(ans.decode('cp437'))
                        sys.stdout.flush()
                    else:
                        # Don't echo what I sent, and clear it up
                        LastDataSent = ''
                    # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                    # it will give false positives tho.. we should find a better way to handle this.
                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass

class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share, transport):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.transport = transport
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        #self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port=self.port,
                                            preferredDialect=dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        if self.transport.get_kerberos() is True:
            self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey,
                                              kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
        else:
            self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share))
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_get(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

        self.send_data('\r\n')

    def do_put(self, s):
        try:
            if self.transferClient is None:
                self.connect_transferClient()
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = '/'

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            f = dst_path + '/' + src_file
            pathname = f.replace('/','\\')
            logging.info("Uploading %s to %s\\%s" % (src_file, self.share, dst_path))
            if PY3:
                self.transferClient.putFile(self.share, pathname, fh.read)
            else:
                self.transferClient.putFile(self.share, pathname.decode(sys.stdin.encoding), fh.read)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            pass

        self.send_data('\r\n')

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        if PY3:
            self.send_data(line.encode('cp437')+b'\r\n')
        else:
            self.send_data(line.decode(sys.stdin.encoding).encode('cp437')+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share, self.transport)
        self.shell.cmdloop()

# # Process command-line arguments.
# if __name__ == '__main__':
#     # Init the example's logger theme
#     logger.init()
#     print(version.BANNER)
#
#     parser = argparse.ArgumentParser(add_help = True, description = "PSEXEC like functionality example using RemComSvc.")
#
#     parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
#     parser.add_argument('command', nargs='*', default = ' ', help='command (or arguments if -c is used) to execute at '
#                                                                   'the target (w/o path) - (default:cmd.exe)')
#     parser.add_argument('-c', action='store',metavar = "pathname",  help='copy the filename for later execution, '
#                                                                          'arguments are passed in the command option')
#     parser.add_argument('-path', action='store', help='path of the command to execute')
#     parser.add_argument('-file', action='store', help="alternative RemCom binary (be sure it doesn't require CRT)")
#     parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
#
#     group = parser.add_argument_group('authentication')
#
#     group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
#     group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
#     group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
#                        '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
#                        'ones specified in the command line')
#     group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
#                                                                             '(128 or 256 bits)')
#
#     group = parser.add_argument_group('connection')
#
#     group.add_argument('-dc-ip', action='store', metavar="ip address",
#                        help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
#                             'the target parameter')
#     group.add_argument('-target-ip', action='store', metavar="ip address",
#                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
#                             'This is useful when target is the NetBIOS name and you cannot resolve it')
#     group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
#                        help='Destination port to connect to SMB Server')
#     group.add_argument('-service-name', action='store', metavar="service name", default = '', help='This will be the name of the service')
#
#     if len(sys.argv)==1:
#         parser.print_help()
#         sys.exit(1)
#
#     options = parser.parse_args()
#
#     if options.debug is True:
#         logging.getLogger().setLevel(logging.DEBUG)
#     else:
#         logging.getLogger().setLevel(logging.INFO)
#
#     import re
#
#     domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
#         options.target).groups('')
#
#     #In case the password contains '@'
#     if '@' in remoteName:
#         password = password + '@' + remoteName.rpartition('@')[0]
#         remoteName = remoteName.rpartition('@')[2]
#
#     if domain is None:
#         domain = ''
#
#     if options.target_ip is None:
#         options.target_ip = remoteName
#
#     if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
#         from getpass import getpass
#         password = getpass("Password:")
#
#     if options.aesKey is not None:
#         options.k = True
#
#     command = ' '.join(options.command)
#     if command == ' ':
#         command = 'cmd.exe'
#
#     executer = PSEXEC(command, options.path, options.file, options.c, int(options.port), username, password, domain, options.hashes,
#                       options.aesKey, options.k, options.dc_ip, options.service_name)
#     executer.run(remoteName, options.target_ip)
