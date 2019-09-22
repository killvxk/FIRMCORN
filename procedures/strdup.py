
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class strdup():
    def __init__(self , fc ,hc , enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug
    def run(self ):
        print "strdup"
        src_addr  = self.fc.reg_read(self.hc.REG_ARGS[0])
        if self.enable_debug:
            print "src_addr : 0x{}".format(str(src_addr).encode)
        src_str = self.fc.mem_read(src_addr , 0x400).split("\x00")
        self.fc.mem_map(0x6000 , 1024 * 1024)
        self.fc.mem_write(0x6000 , str(src_str))