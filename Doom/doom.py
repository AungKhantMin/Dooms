import sys

from Doom.module.cmd import Cmd
from Doom.module.color import C

print(C.FAIL+C.BOLD+'''


                     /$$$$$$$  /$$$$$$  /$$$$$$ /$$      /$$      
                    | $$__  $$/$$__  $$/$$__  $| $$$    /$$$      
                    | $$  \ $| $$  \ $| $$  \ $| $$$$  /$$$$      
                    | $$  | $| $$  | $| $$  | $| $$ $$/$$ $$      
                    | $$  | $| $$  | $| $$  | $| $$  $$$| $$      
                    | $$  | $| $$  | $| $$  | $| $$\  $ | $$      
                    | $$$$$$$|  $$$$$$|  $$$$$$| $$ \/  | $$      
                    |_______/ \______/ \______/|__/     |__/      
                                                                                                                                                                                                                                                                                                                                           
                    Developed By 4BE-IT-GROUP-3 (WYTU)
                                                                                                                                                                                                                                                                                      
'''+C.ENDC)

cmd = Cmd()
cmd.loop()
