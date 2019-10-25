from Doom.module.dns import DNS
from Doom.module.gobuster import GOBUSTER
from Doom.module.smb_enum import SMB_ENUM
from Doom.module.smb_vuln import SMB_VULN
from Doom.module.color import C
from Doom.module.ftp_enum import FTP_ENUM
from Doom.module.nmap import NMAP
from os import system

class Cmd(object):

    line = ""

    def __init__(self):
        self.module = ""
        self.avaliable_module = ['smb_enum','ftp_enum','ftp_vuln','gobuster','smb_vuln','dns','nmap']
        self.obj = None

    def parser(self,command : str):
        commands = command.split(" ")
        return  commands

    def prompt(self):
        if self.module != "":
            return  "doom module("+ C.BOLD+C.FAIL +"%s" % self.module+ C.ENDC + ") > "
        else:
            return "doom > "

    def loop(self):
        while True:
            prompt = self.prompt()
            command = input(prompt)
            parse_command = self.parser(command)
            self.analyzeCommand(parse_command)

    def analyzeCommand(self,parse_commands : list, module=""):
        try:
            if 'use' in parse_commands[0]:
                self.module = parse_commands[1]
                if str.lower(self.module) in self.avaliable_module:
                    self.obj = eval(str.upper(self.module))()
                else:
                    print(C.BOLD+C.FAIL+"No module name %s" % self.module + C.ENDC)
            elif self.obj is not None:
                if 'help' == str.lower(parse_commands[0]):
                    self.obj.show_help()
                elif 'show' in parse_commands[0]:
                    cmd = parse_commands[1]
                    if 'options' == str.lower(cmd):
                        self.obj.show_options()
                elif 'set' == str.lower(parse_commands[0]):
                    opt = str.lower(parse_commands[1])
                    arg = str.lower(parse_commands[2])
                    if opt in self.obj.avaliable_opt:
                        func = getattr(self.obj,'set_'+opt)
                        func(arg)
                    else:
                        print(C.FAIL+C.BOLD+"No options name %s" % opt)
                elif 'run' == str.lower(parse_commands[0]):
                    self.obj.run()
                elif 'exit' == str.lower(parse_commands[0]):
                    self.module = ""
                    self.obj = None
                else:
                    print(C.BOLD+C.FAIL+"[-] Unknown command : %s" % parse_commands[0] + C.ENDC)

            elif 'exit' == str.lower(parse_commands[0]):
                exit(0)
            elif parse_commands[0] == "":
                pass
            elif parse_commands[0] == "help":
                self.help()
            elif parse_commands[0][0] == "!":
                parse_commands[0] = parse_commands[0][1::]
                cmd = str.join(" ",parse_commands)
                system(cmd)
            else:
                print(C.BOLD+C.FAIL+"[-] Unknown command : %s" % parse_commands[0] + C.ENDC)
        except Exception as e:
            print(C.BOLD+C.FAIL+'[-] ' + str(e) + C.ENDC)


    def help(self):
        print("\n\tShow available commands for current module\n")
        print("\tuse - Select Which module to use")
        print("\tavaliable module - %s" % str(self.avaliable_module) )
        print("\texit - Exit from program")
