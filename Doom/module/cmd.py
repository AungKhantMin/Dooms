from Doom.module.dns import DNS
from Doom.module.gobuster import GoBuster
from Doom.module.smb_enum import SMB_ENUM
from Doom.module.smb_vuln import SMBVulnScan

class C:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Cmd(object):

    line = ""



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

    def analyzeCommand(self,parse_commands : list, module=""):
        if 'use' in parse_commands[0]:
            use = Use()
            use.module = parse_commands[1]
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

    def analyzeCommand(self,parse_commands : list,module =""):
        if 'show' in str.lower(parse_commands[0]):
            if 'help' in str.lower(parse_commands[1]):
                print("will print help")
            elif 'options' in str.lower(parse_commands[1]):
                print("will show require parameter")
        elif 'run' in parse_commands[0]:
            if self.checkParam(self.options):
                self.run()
        elif 'set' in str.lower(parse_commands[0]):

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
