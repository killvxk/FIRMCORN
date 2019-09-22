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
        self.func_list = {}
        self.func_list.update({ 'strcpy': self.strcpy })
        self.func_list.update({ 'scanf' : self.scanf })
        self.func_list.update({ 'memset': self.memset})
        self.func_list.update({ 'sprintf': self.sprintf})
        self.func_list.update({ 'strdup': self.strdup})
    
    def strcpy(self):
        strcpyEmu = strcpy(self.fc, self.hc)
        strcpyEmu.run()
    
    def scanf(self):
        scanfEmu = scanf(self.fc, self.hc)
        scanfEmu.run()
    
    def memset(self):
        memsetEmu = memset(self.fc, self.hc)
        memsetEmu.run()
    
    def sprintf(self):
        sprintfEmu = sprintf(self.fc, self.hc)
        sprintfEmu.run()

    def strdup(self):
        sprintfEmu = strdup(self.fc, self.hc)
        sprintfEmu.run()