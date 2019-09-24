import subprocess
import os 
import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib
from struct import unpack, pack, unpack_from, calcsize

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class CrashLoader():
    def __init__(self  , fc ):
        self.fc = fc 

    def check_stack(self , uc , address , size , user_data):
        instr = mu.mem_read(address , size)

    def mem_crash_check(self, uc, access, address, size, value, user_data):
        print ">>>Err<<< Missing memory is being WRITE at {}".format(hex(address))
 

    def identity_ret(self):
        pass


    def crash_log(self):
        pass
    

    def get_common_ret(self):
        if self.arch == "x64":
            self.RET_INTR = "\xC3"
        elif self.arch == "x32":
            self.RET_INTR = "\xC3"
        elif self.arch == "mips":
            self.RET_INTR = "\x03\xE0\x00\x08"
        elif self.arch == "arm":
            self.uc_arch = UC_ARCH_ARM
            self.uc_mode = UC_MODE_32
        else:
            raise Exception("Error arch")