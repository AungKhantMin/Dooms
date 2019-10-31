#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# ATSVC example for some functions implemented, creates, enums, runs, delete jobs
# This example executes a command on the target machine through the Task Scheduler
# service. Returns the output of such command
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for TSCH
from __future__ import division
from __future__ import print_function
import string
import sys
import argparse
import time
import random
import logging

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE


class TSCH_EXEC:
    def __init__(self, ip = "" , username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 command= ''):
        self.target = ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__command = command
        self.addr = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def set_target(self, ip):
        self.target = ip
        print("TARGET => %s" % self.target)

    def set_user(self, username):
        self.__username = username
        print("USERNAME => %s" % self.__username)

    def set_password(self, password):
        self.__password = password
        print("PASSWORD => %s" % self.__password)



    def show_help(self):
        print('''
        This software is provided under under a slightly modified version
        of the Apache Software License. See the accompanying LICENSE file
        for more information.

        ATSVC example for some functions implemented, creates, enums, runs, delete jobs
        This example executes a command on the target machine through the Task Scheduler
        service. Returns the output of such command''')

    def show_options(self):
        print("\n\Show available option for this module")
        print("\tUSERNAME - USERNAME USE TO AUTHENTICATE TO REMOTE SERVER")
        print("\tPASSWORD - PASSWORD  USE TO AUTHENTICATE TO REMOTE SERVER")
        print("\tDOMAIN")
        print("\tHASHES - NTLM hashes, format is LMHASH:NTHASH")
        print("\tAESKEY - AES key to use for Kerberos Authentication (128 or 256 bits)")
        print("\tKERBEROES - Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
        print("\tDC_IP - IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
        print("\t' '")
        print("\tJOIN(OPTIONS.COMMANDS)")
    def exec(self):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.doStuff(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport):
        def output_callback(data):
            print(data.decode('utf-8'))

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        # dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        tmpFileName = tmpName + '.tmp'

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C %s &gt; %%windir%%\\Temp\\%s 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % (self.__command, tmpFileName)
        taskCreated = False
        try:
            logging.info('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.info('Running task \\%s' % tmpName)
            tsch.hSchRpcRun(dce, '\\%s' % tmpName)

            done = False
            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            logging.info('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        smbConnection = rpctransport.get_smb_connection()
        waitOnce = True
        while True:
            try:
                logging.info('Attempting to read ADMIN$\\Temp\\%s' % tmpFileName)
                smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                break
            except Exception as e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    if waitOnce is True:
                        # We're giving it the chance to flush the file before giving up
                        time.sleep(3)
                        waitOnce = False
                    else:
                        raise
                else:
                    raise
        logging.debug('Deleting file ADMIN$\\Temp\\%s' % tmpFileName)
        smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)

        dce.disconnect()


# Process command-line arguments.
