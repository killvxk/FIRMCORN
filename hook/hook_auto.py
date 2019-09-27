import sys
import logging 
import os
import json
from pwn import *

from func_emu import *
from hook_auto import *

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class HookAuto():
    """
    heuristic method
    """
    def __init__(self , fc , hc):
        self.fc = fc 
        self.hc = hc
        self.last_func = ""

    def record_last_func(self , uc , address , size , user_data):
        # if self.fc.mem_got
        if self.fc.mem_got.get(address) and self.fc.rebase_got.get(self.fc.mem_got[address]):
            self.last_func = self.fc.mem_got[address]

    def find_unresolved_func(self, uc, access, address, size, value, user_data):
        self.fc.unresolved_funcs.append(self.last_func)
        print "find unresolved func : {}".format(self.last_func)