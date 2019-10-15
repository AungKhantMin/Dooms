import sys

from Doom.module.dns import DNS
from Doom.module.gobuster import GoBuster
from Doom.module.smb_enum import SMBEnum
from Doom.module.smb_vuln import SMBVulnScan


class Cmd(object):

    line = ""

    def __init__(self):
        self.HEADER = '\033[95m'
        self.OKBLUE = '\033[94m'
        self.OKGREEN = '\033[92m'
        self.WARNING = '\033[93m'
        self.FAIL = '\033[91m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'

    def parser(self,command : str):
        commands = command.split(" ")
        return  commands

    def prompt(self,line = ""):
        if line != "":
            return  "doom module(%s) > " % line
        else:
            return "doom > "

    def loop(self):
        prompt = self.prompt()
        while True:
            command = input(prompt)
            parse_command = self.parser(command)
            self.analyzeCommand(parse_command)

    def analyzeCommand(self,parse_commands : list):
        if 'use' in parse_commands[0]:
            use = Use()
            use.loop(parse_commands[1])

    def checkParam(self, options : list):
        pass

    def run(self):
        pass

class Use(Cmd):
    def __init__(self):
        super(Cmd).__init__()
        self.options = []
        self.module = ""

    def analyzeCommand(self,parse_commands : list):
        if 'show' in parse_commands[0]:
            if 'help' in parse_commands[1]:
                print("will print help")
            elif 'options' in parse_commands[1]:
                print("will show require parameter")
        elif 'run' in parse_commands[0]:
            if self.checkParam(self.options):
                self.run()

    def checkParam(self,options : list):
        pass

    def setParam(self):
        pass

    def run(self):
        pass

    def loop(self,msg=""):
        prompt = self.prompt(msg)
        while True:
            command = input(prompt)
            parse_command = self.parser(command)
            self.analyzeCommand(parse_command)

class Set(Use):
    def __init__(self):
        super(Use).__init__()

    def analyzeCommand(self, parse_commands: list):
        if 'set' in parse_commands[0]:
            if self.line == 'smb_enum':
                smben = SMBEnum()
                # set0 target1 blahblah2 user3 blah4 pass5 blah6
                smben.setTarget(parse_commands[2])
                smben.setUser(parse_commands[4])
                smben.setPass(parse_commands[6])

            if self.line == 'smb_vuln':
                smbVS = SMBVulnScan()
                # set0 target1 blahblah2 pass3 blah4
                smbVS.setTarget(parse_commands[2])
                smbVS.setPass(parse_commands[4])

            if self.line == 'gobuster':
                gb = GoBuster()
                # set0 target1 blahblah2 port3 blah4 thread5 blah6
                gb.setTarget(parse_commands[2])
                gb.setPort(parse_commands[4])
                gb.setThread(parse_commands[6])

            if self.line == 'dns':
                smbVS = DNS()
                # set0 target1 blahblah2 zone3 blah4
                smbVS.setTarget(parse_commands[2])
                smbVS.setZone(parse_commands[4])

cmd = Cmd()

cmd.loop()
