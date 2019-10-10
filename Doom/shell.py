import cmd

from modules.network import *


class DoomShell(cmd.Cmd):
    intro = "Doom Information Gathering and Vulnerable Analysis Framework\n"
    prompt = "doom >"
    file = None

    def do_use(self,arg):
        '''
            Choose What Module To Use. Eg. use module/network
        '''

    def do_exit(self,arg):
        '''
            Exist From The Current Session
        :return:
        '''

        exit()
