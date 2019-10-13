import cmd

class Shell(cmd.Cmd):
    def do_prompt(self,prompt=""):
        if prompt != "":
            self.prompt = "doom module(%s) > " % prompt
        else:
            self.prompt = "doom >"

    def do_help(self, arg):
        print("ggwp")

    def do_use(self,module):
        self.do_prompt(module)

    def do_show_options(self):
        print("test")

class Module(cmd.Cmd):
    def do_show(self):
        pass

shell = Shell()
shell.do_prompt()
shell.cmdloop()
