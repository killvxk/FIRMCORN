import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *

sys.path.append('../')
from procedures import *


INPUT_BASE = 0x300000


class FuncEmu(object):
    """
    # simulation of common function
    """ 
    def __init__(self , fc ,  hc , enable_debug=True):
        # pass
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object(this is not a good implementation...)
        self.debug_func = enable_debug
    
    
    def strcpy(self):
        strcpyEmu = strcpy(fc, hc)
        strcpyEmu.run()
    
    def scanf(self):
        scanfEmu = scanf(fc, hc)
        scanfEmu.run()
    
    def memset(self):
        memsettEmu = memset(fc, hc)
        memsetEmu.run()
    
    def sprintf(self):
        sprintfEmu = sprintf(fc, hc)
        sprintfEmu.run()
