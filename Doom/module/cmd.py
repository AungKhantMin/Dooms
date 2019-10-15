import sys

class Cmd(object):
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


cmd = Cmd()

cmd.loop()
