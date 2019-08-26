import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib
# from pwn import * 
# import unicorn

# Unicorn imports
# require unicorn moudle
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


# there are simulation of common function

INPUT_BASE = 0x300000


class FuncEmu(object):
    def __init__(self , fc ,  hc , enable_debug=True):
        # pass
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object(this is not a good implementation...)
        self.debug_func = enable_debug


    def _strcpy(self , args):
        # pass
        # print "hook by strcpy"
        dest_addr  = self.fc.reg_read(self.hc.REG_ARGS[0])
        src_addr = self.fc.reg_read(self.hc.REG_ARGS[1])
        src_str = self.fc.mem_read(src_addr , 0x10)
        if self.debug_func:
            print "src: {} ; dest: {}".format(hex(src_addr) , hex(dest_addr))
        if self.debug_func:
            print "scanf buf: {}".format(self.fc.mem_read(0x7fffffffdb30,0x10) )
        self.fc.mem_write(dest_addr - len(str(src_str)) , str(src_str)) # stack isfrom high to low
        if self.debug_func:
            print "check the stack: {}".format(self.fc.mem_read(self.fc.reg_read(self.hc.REG_SP) , self.hc.size) )
    
    def _getenv(self , args):
        pass
    
    def _printf(self , args):
        print("this is hook output: %d" % args[1])
        return 0
    
    def _scanf(self , args , debug_func = True):
        # maybe we have to think about all instruction
        # # need to be changed
        inputs_dir = "/home/b1ngo/Firmcorn/inputs/" 
        inputs_bin = "1.bin"
        inputs_file = open(inputs_dir + inputs_bin, "rb")
        inputs = inputs_file.read()
        inputs_file.close()
        fmt = self.fc.reg_read(self.hc.REG_ARGS[0])
        buf = self.fc.reg_read(self.hc.REG_ARGS[1])
        if self.debug_func:
            print "fmt: {} ; buf : {:#x}".format(fmt , buf)
        self.fc.mem_write(buf , inputs)
        if self.debug_func:
            print "scanf buf: {}".format(self.fc.mem_read(0x7fffffffdb30,0x10) )
        print "scanf compelte"
        return 0


    def _memset(self , args):
        return 0