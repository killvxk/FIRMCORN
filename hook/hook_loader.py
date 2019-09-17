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

# https://github.com/36hours/idaemu
# very enlightening
COMPILE_GCC = 1
COMPILE_MSVC = 2

# The class for hook and  hijack function
class HookCode(object):
    def __init__(self , fc , arch , compiler=COMPILE_GCC, enable_debug = False):
        # pass
        self.fc = fc 
        self.arch = arch
        self.func_alt_addr = {}
        self.func_skip_list = []
        self.compiler = compiler
        self.debug_func = enable_debug
        self.get_common_regs() 


    def func_alt(self , address , func , argc , debug_func = True):
        # fake func fmt : (func , argc)
        self.debug_func = debug_func
        self.func_alt_addr[address] = (func , argc )

        # use for hijack function , like getenv , printf .etc
    def _func_alt(self , uc , address , size , user_data):
        # print "hook code success"
        # The essence of function hijacking is to skip 
        # over the function and set the return content according to 
        # the function function, according to the parameters, 
        # and also set the stack balance for addres 
        if self.debug_func:
            # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
            pass
        if address in self.func_alt_addr.keys():
            # keep balance may be need to 
            # consider in the future
            # fake func fmt : (func , args)
            func , argc  = self.func_alt_addr[address]
            if self.debug_func:
                print  "func : {0} ; argc : {1}".format(func, argc)
            # fc <==> firmcorn class <--- Uc class
            # 1 , get return address
            reg_sp = self.fc.reg_read(self.REG_SP)
            # we should get address value from stack
            if self.REG_RA == 0: 
                ret_addr = unpack(self.pack_fmt , str(self.fc.mem_read(reg_sp , self.size)))[0]
            else:
                ret_addr = self.fc.reg_read(self.REG_RA)
            # 2 , get args by argc
            if self.debug_func:
                print "ret_addr : {}".format(hex(ret_addr))
            args = []
            i = 0
            while i < argc and i<len(self.REG_ARGS):
                args.append(self.fc.reg_read(self.REG_ARGS[i]))
                i +=1
            '''
            # if argc > len(self.REG_ARGS)
            sp2 = sp
            while i < argc:
                args.append(unpack(self.pack_fmt, str(uc.mem_read(sp2, self.step)))[0])
                sp2 += self.step
                i += 1
            '''
            # 3 , execute custom function and get return value
            res = func(args) # not very understand , need debug
            if self.debug_func:
                print "ret_addr : {0}; args : {1}; res : {2}".format(ret_addr , args , res)
            if type(res) != int: res = 0 # return value is not very import for fuzz , easpically return value is not int type
            self.fc.reg_write(self.REG_RES , res)
            self.fc.reg_write(self.REG_PC , ret_addr)
            '''
            # maybe need to keep stack balace
            pass 
            '''


    def func_skip( self , func_skip_list , debug_func = True):
        # setup func skip list 
        self.debug_func = debug_func
        self.func_skip_list = func_skip_list

    def _func_skip(self  ,  uc , address , size , user_data):
        if address in self.func_skip_list:
            if self.debug_func:
                print "address skip:{:#x}".format(address)
            self.fc.reg_write( self.REG_PC ,  address+size)

    def get_common_regs(self):
        # get some common register
        # REG_PC: IP
        # REG_SP: stack pointer 
        # REG_RA: return address (just like arm $lr and mips $ra)
        # REG_ARGS: args 
        # REG_RES: return value
        # arch to uc_arch
        if self.arch == "x64":
            self.uc_arch =  UC_ARCH_X86
            self.uc_mode = UC_MODE_64
        elif self.arch == "x32":
            self.uc_arch = UC_ARCH_X86
            self.uc_mode = UC_MODE_32
        elif self.arch == "mips":
            self.uc_arch = UC_ARCH_MIPS
            self.uc_mode = UC_MODE_32
        elif self.arch == "arm":
            self.uc_arch = UC_ARCH_ARM
            self.uc_mode = UC_MODE_32
        else:
            raise Exception("Error arch")

        if self.uc_arch == UC_ARCH_X86:
            if self.uc_mode == UC_MODE_16:
                self.size = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.uc_mode == UC_MODE_32:
                self.size = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.uc_mode == UC_MODE_64:
                self.size = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                    # print "test"
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.uc_arch == UC_ARCH_ARM:
            if self.uc_mode == UC_MODE_ARM:
                self.size = 4
                self.pack_fmt = '<I'
            elif self.uc_mode == UC_MODE_THUMB:
                self.size = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.uc_arch == UC_ARCH_ARM64:
            self.size = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        elif self.uc_arch == UC_ARCH_MIPS:
            self.size = 8
            self.pack_fmt = "<I"
            self.REG_PC = UC_MIPS_REG_PC
            self.REG_SP = UC_MIPS_REG_SP
            self.REG_RA = UC_MIPS_REG_RA
            self.REG_RES = [UC_MIPS_REG_V0, UC_MIPS_REG_V1,UC_MIPS_REG_V1]
            self.REG_ARGS = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]