import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib
from pwn import * 
# import unicorn

# Unicorn imports
# require unicorn moudle
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *

# custom module import 
from hook.hook_loader import *
from hook.func_emu import *
from fuzz.fuzz_loader import *
from crash.crash_loader import *

# Name of the index file
CONTEXT_JSON = "_index.json"

# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Max allowable segment size (1G)
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024
    
# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP   = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)


BASE = 0x0400000


class Firmcorn( Uc ): # Firmcorn object inherit from Uc object  
    '''
    Firmcorn-object is main object of our Firmcorn Framework
    '''
    def __init__(self   , enable_debug = True):
        # pass
        # self.files = files
        # self.context_dir = context_dir
        self.enable_debug = enable_debug
        self.trace_start_addr = 0
        self.trace_end_addr = 0
        self.dbg_addr_list = []
        # self.files = files  
        # init unciorn enigne


    def load_context(self , context_dir , binary ):
        self.elf = ELF(binary)
        self.got = self.elf.got

        
        self.context_dir = context_dir
        context_json = os.path.join( self.context_dir, CONTEXT_JSON)
        if not os.path.isfile(context_json):
            raise Exception("Contex json not found")
        
        # load context from json
        context_json_file  = open(context_json , "r")
        context = json.load(context_json_file) # load _index.json
        context_json_file.close()

        # check context file is complete
        if 'arch' not in context:
            raise Exception("Couldn't find architecture information in index file")
        if 'regs' not in context:
            raise Exception("Couldn't find register information in index file")
        if 'segments' not in context:
            raise Exception("Couldn't find segment/memory information in index file")
        
        
        self.arch = context['arch']['arch']
        self.endian = context['arch']['endian']
        # load registers
        regs_map = self.getRegsByArch(self.arch)
        regs = context['regs']

        # init some class
        # we get self.hookcode
        self.init_class()

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
        
        self.get_common_regs()

        # endian to uc_endian
        if self.endian == "big":
            self.uc_endian =  UC_MODE_BIG_ENDIAN
        else:
            self.uc_endian =  UC_MODE_LITTLE_ENDIAN
        # init uc object
        # self = Uc(self.uc_arch , self.uc_mode)
        Uc.__init__(self, self.uc_arch, self.uc_mode + self.uc_endian)

        if not self.set_reg(regs , regs_map):
            raise Exception("Error in setup registers")

        # setup segment
        segments_list = context['segments'] # 
        if not self.set_memory(segments_list):
            raise Exception("Error in setup memory")

        self.init_got()


    def init_got(self , enable_debug = True):
        """
        Read GOT table entries in memory 
        """
        print "=======================================Init GOT Table Start======================================="
        if self.got is not None and self.enable_debug:
            print self.got  

        for name , addr in self.got.items():
            print int(str(self.mem_read(addr , self.size)).encode("hex") , 16)
            self.got.update({ int(str(self.mem_read(addr , self.size)).encode("hex") , 16): name})
            print "Name : {:<40} Addr : {:<10} Value: 0x{:<10}".format( name, hex(addr) , str(self.mem_read(addr , self.size)).encode("hex"))
        print "=======================================Init GOT Table End=========================================="
    
    def dbg_hook_code(mu, address, size, user_data):  
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    def debug_moudle(self , start_addr , end_addr):
        """
        debug 
        """
        dbg_mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
        dbg_mu.hook_add(UC_HOOK_CODE, self.dbg_hook_code)
        dbg_mu.emu_start(start_addr )

    def set_reg(self , regs, regs_map , debug_func = True ):
        self.enable_debug = debug_func
        # setup register
        for register , value in regs.iteritems():
            if self.enable_debug:
                print "Reg {0} = {1}".format(register, hex(value)) 
                pass
            if not regs_map.has_key(register.lower()):
                if self.enable_debug:
                    print "Skip Reg:{0}".format(register)
            else:
                # ====copy from unicorn loader.py=====
                # 
                reg_write_retry = True
                try:
                    self.reg_write(regs_map[register.lower()], value)
                    reg_write_retry = False
                except Exception as e:
                    if self.enable_debug:
                        print "ERROR writing register: {}, value: {} -- {}".format(register, value, repr(e)) 
                if reg_write_retry:
                    if self.enable_debug:
                        print "Trying to parse value ({}) as hex string".format(value)
                    try:
                        self.reg_write(regs_map[register.lower()], int(value, 16))
                    except Exception as e:
                        if self.enable_debug:
                            print "ERROR writing hex string register: {}, value: {} -- {}".format(register, value, repr(e))
        
        return True


    def set_memory(self , segments_list , debug_func = False  ):
        self.enable_debug = debug_func
        # setup memory need 2 steps
        # 1. mu.mem_map
        # 2. mu.mem_write
        # before mem_map, must check it's not already mapped
        # copy from __map_segments
        for segment in segments_list:
            seg_name = segment['name']
            seg_start = segment['start']
            seg_end = segment['end']
            perms = \
                (UC_PROT_READ  if segment['permissions']['r'] == True else 0) | \
                (UC_PROT_WRITE if segment['permissions']['w'] == True else 0) | \
                (UC_PROT_EXEC  if segment['permissions']['x'] == True else 0)        

            if self.enable_debug:
                print "Handling segment {}".format(seg_name) 
            """
            before map memory , do some check
            there are 3 cases:
            ======= 1 =======
            +----------------------------+ <-----+ mem_start
            |                            |
            |  +----------------------+<----+  seg_start
            |  |                      |  |
            |  |                      |  |
            |  +----------------------+<----+  seg_end
            |                            |
            +----------------------------+ <-----+  mem_end
            for this case, shoud't map memory 

            ======= 2 =======
            +-----------------------------+<-----+ mem_start
            |                             |
            |                             |
            +------------------------------<----+  seg_start
            |                             |
            |                             |
            |                             |
            +------------------------------<-----+  mem_end=tmp
            |-----------------------------|
            |--------------------------------------------->map area
            |-----------------------------|
            +------------------------------<----+  seg_end
            
            ======= 3 =======
            +------------------------------<----+  seg_start
            |-----------------------------|
            |--------------------------------------------->map area
            |-----------------------------|
            +------------------------------<-----+ mem_start=tmp
            |                             |
            |                             |
            |                             |
            +------------------------------<----+  seg_end
            |                             |
            |                             |
            |                             |
            +-----------------------------+<-----+  mem_end
            """
            found = False
            overlap_start = False
            overlap_end = False
            tmp = 0
            for (mem_start, mem_end, mem_perm) in self.mem_regions():
                mem_end = mem_end + 1
                if seg_start >= mem_start and seg_end < mem_end:
                    found = True
                    break
                if seg_start >= mem_start and seg_start < mem_end:
                    overlap_start = True
                    tmp = mem_end
                    break
                if seg_end >= mem_start and seg_end < mem_end:
                    overlap_end = True
                    tmp = mem_start
                    break

            # Map memory into the address space if it is of an acceptable size.
            if (seg_end - seg_start) > MAX_ALLOWABLE_SEG_SIZE:
                if self.enable_debug:
                    print "Skipping segment (LARGER THAN {0}) from {1:016x} - {2:016x} with perm={3}: {4}".format(MAX_ALLOWABLE_SEG_SIZE, seg_start, seg_end, perms, name)
                continue
            elif not found:           # Make sure it's not already mapped
                if overlap_start:     # Partial overlap (start) case 3
                    self.map_segment(seg_name, tmp, seg_end - tmp, perms)
                elif overlap_end:       # Patrial overlap (end) case 2
                    self.map_segment(seg_name, seg_start, tmp - seg_start, perms)
                else:                   # Not found
                    self.map_segment(seg_name, seg_start, seg_end - seg_start, perms)
            else:
                if self.enable_debug:
                    print "Segment {} already mapped. Moving on.".format(seg_name) 

            # Load the content (*.bin)
            # directly copy from unicorn_loader.py
            if 'content_file' in segment and len(segment['content_file']) > 0:
                content_file_path = os.path.join(self.context_dir, segment['content_file'])
                if not os.path.isfile(content_file_path):
                    raise Exception("Unable to find segment content file. Expected it to be at {}".format(content_file_path))
                if self.enable_debug:
                    print "Loading content for segment {} from {}".format(seg_name, segment['content_file'])
                content_file = open(content_file_path, 'rb')
                compressed_content = content_file.read()
                content_file.close()
                self.mem_write(seg_start, zlib.decompress(compressed_content)) 

            else:
                if self.enable_debug:
                    print("No content found for segment {0} @ {1:016x}".format(seg_name, seg_start))
                self.mem_write(seg_start, '\x00' * (seg_end - seg_start))


        return True


    def map_segment(self , name, address, size, perms , debug_func = False ):
        self.enable_debug = debug_func
        map_start = address 
        map_end = address + size
        # page alingn
        map_start_align = ALIGN_PAGE_DOWN(map_start)
        map_end_align = ALIGN_PAGE_UP(map_end)
        if self.enable_debug:
            print " segment name: {}".format(name)
            print " segment start: {0:016x} -> {1:016x}".format(map_start, map_start_align)
            print " segment end:   {0:016x} -> {1:016x}".format(map_end, map_end_align)
        if map_start_align < map_end_align: 
            self.mem_map(map_start_align , map_end_align - map_start_align , perms) # map memory

        # pass


    def set_trace(self , trace_start_addr , trace_end_addr  , debug_func=True):
        self.trace_start_addr = trace_start_addr
        self.trace_end_addr = trace_end_addr


    def _set_trace(self , uc , address , size , user_data):
        if address >= self.trace_start_addr and self.trace_end_addr:
            if self.enable_debug:
                print "trace address"
            print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
            instr = self.mem_read(address, size)
            # context.arch      = 'i386'
            context.endian    = str(self.endian)
            # context.os        = 'linux'
            # context.word_size = 32
            # print ("0x%x %s" % (address - BASE ,   disasm(instr)) )
            if self.arch == "x64" or self.arch == "x32":
                print "{}".format( disasm(instr , arch="{}".format("i386")))
            print "{}".format( disasm(instr , arch="{}".format("mips")))
    
    def _show_debug_info(self, uc , address , size , user_data ):
        """
        show registers and memory info when debug
        """
        
        context_json = os.path.join( self.context_dir, CONTEXT_JSON)
        if not os.path.isfile(context_json):
            raise Exception("Contex json not found")
        
        # load context from json
        context_json_file  = open(context_json , "r")
        context = json.load(context_json_file) # load _index.json
        context_json_file.close()
        regs_map = self.getRegsByArch(self.arch)
        regs = context['regs']
        
        if address in self.dbg_addr_list:
            # show registers value
            print("=================================================================")
            print("=========================Registers Value=========================")
            for register , value in regs.iteritems():
                try:
                    print("Reg {} --> {}".format(register.lower() ,hex(self.reg_read(regs_map[register.lower()])) ))
                except Exception as e:
                    print "ERROR writing register: {}, value: {} -- {}".format(register, value, repr(e))
            

            print("=================================================================")
            # print("")
            print("=========================Memory Content==========================")
            # show stack memory
            for i in range(6):
                reg_sp = self.reg_read(self.REG_SP , size)
                stack_addr = reg_sp + 288 + 4*i
                mem_cont = self.mem_read(stack_addr, 4)
                print("sp+{} {} --> {}".format( 288 + 4*i , hex(stack_addr) ,str(mem_cont).encode("hex")))
            
            # show other memory
            addr = self.reg_read(UC_MIPS_REG_S0, size) 
            print("{} --> 0x{}".format( hex(addr) , str(self.mem_read(addr, 4)).encode("hex")))

    def show_debug_info(self , dbg_addr_list):
        self.dbg_addr_list = dbg_addr_list


    def add_fuzz(self, fuzzTarget):
        # use to add a fuzz targrt object
        if fuzzTarget is not None:
            fuzzTarget.init(self, self.arch)
            self.hook_add(UC_HOOK_CODE , fuzzTarget.fuzz_func_alt)
        # add crash 
        # crashTarget = CrashTarget()
        # crashTarget.init(self, self.arch)
        # elf.hook_add(UC_HOOK_CODE , crashTarget.check_crash)


    def start_run(self , start_address , end_address , fuzzTarget=None):
        print "  ______ _____ _____  __  __  _____ ____  _____  _   _ "
        print " |  ____|_   _|  __ \|  \/  |/ ____/ __ \|  __ \| \ | |"
        print " | |__    | | | |__) | \  / | |   | |  | | |__) |  \| |"
        print " |  __|   | | |  _  /| |\/| | |   | |  | |  _  /| . ` |"
        print " | |     _| |_| | \ \| |  | | |___| |__| | | \ \| |\  |"
        print " |_|    |_____|_|  \_\_|  |_|\_____\____/|_|  \_\_| \_|"
        print "                                                       "
        # uc_result = self.emu_start(start_address , end_address)
        if self.hookcode.func_alt_addr is not None:
            self.hook_add(UC_HOOK_CODE , self.hookcode._func_alt) 
        if self.hookcode.func_skip_list is not None:
            self.hook_add(UC_HOOK_CODE , self.hookcode._func_skip)
        if self.dbg_addr_list is not None:
            self.hook_add(UC_HOOK_CODE, self._show_debug_info)
        if self.trace_start_addr!=0 and self.trace_end_addr!=0:
            self.hook_add(UC_HOOK_CODE , self._set_trace)
        if self.got is not None:
            self.hook_add(UC_HOOK_CODE , self.hookcode.func_alt_dbg)


        import pdb
        # pdb.set_trace()
        uc_result = self.emu_start(start_address , end_address)
        # try:
        #     uc_result = self.emu_start(start_address , end_address)
        #     # need to add fuzz_start
        # except:
        #     print "emu_start error"
        # pass
        


    def init_class(self): 
        # this part import hook module 
        # return Hooker class
        self.hookcode = Hooker(self , self.arch )
        self.funcemu = FuncEmu(self , self.hookcode)
        
        


    def getRegsByArch(self , arch):
        if arch == "arm64le" or arch == "arm64be":
            arch = "arm64"
        elif arch == "armle" or arch == "armbe" or "thumb" in arch:
            arch = "arm"
        elif arch == "mipsel":
            arch = "mips"

        registers = {
            "x64" : {
                "rax":    UC_X86_REG_RAX,
                "rbx":    UC_X86_REG_RBX,
                "rcx":    UC_X86_REG_RCX,
                "rdx":    UC_X86_REG_RDX,
                "rsi":    UC_X86_REG_RSI,
                "rdi":    UC_X86_REG_RDI,
                "rbp":    UC_X86_REG_RBP,
                "rsp":    UC_X86_REG_RSP,
                "r8":     UC_X86_REG_R8,
                "r9":     UC_X86_REG_R9,
                "r10":    UC_X86_REG_R10,
                "r11":    UC_X86_REG_R11,
                "r12":    UC_X86_REG_R12,
                "r13":    UC_X86_REG_R13,
                "r14":    UC_X86_REG_R14,
                "r15":    UC_X86_REG_R15,
                "rip":    UC_X86_REG_RIP,
                "rsp":    UC_X86_REG_RSP,
                "efl":    UC_X86_REG_EFLAGS,
                "cs":     UC_X86_REG_CS,
                "ds":     UC_X86_REG_DS,
                "es":     UC_X86_REG_ES,
                "fs":     UC_X86_REG_FS,
                "gs":     UC_X86_REG_GS,
                "ss":     UC_X86_REG_SS,
            },
            "x86" : {
                "eax":    UC_X86_REG_EAX,
                "ebx":    UC_X86_REG_EBX,
                "ecx":    UC_X86_REG_ECX,
                "edx":    UC_X86_REG_EDX,
                "esi":    UC_X86_REG_ESI,
                "edi":    UC_X86_REG_EDI,
                "ebp":    UC_X86_REG_EBP,
                "esp":    UC_X86_REG_ESP,
                "eip":    UC_X86_REG_EIP,
                "esp":    UC_X86_REG_ESP,
                "efl":    UC_X86_REG_EFLAGS,        
                # Segment registers removed...
                # They caused segfaults (from unicorn?) when they were here
            },        
            "arm" : {
                "r0":     UC_ARM_REG_R0,
                "r1":     UC_ARM_REG_R1,
                "r2":     UC_ARM_REG_R2,
                "r3":     UC_ARM_REG_R3,
                "r4":     UC_ARM_REG_R4,
                "r5":     UC_ARM_REG_R5,
                "r6":     UC_ARM_REG_R6,
                "r7":     UC_ARM_REG_R7,
                "r8":     UC_ARM_REG_R8,
                "r9":     UC_ARM_REG_R9,
                "r10":    UC_ARM_REG_R10,
                "r11":    UC_ARM_REG_R11,
                "r12":    UC_ARM_REG_R12,
                "pc":     UC_ARM_REG_PC,
                "sp":     UC_ARM_REG_SP,
                "lr":     UC_ARM_REG_LR,
                "cpsr":   UC_ARM_REG_CPSR
            },
            "arm64" : {
                "x0":     UC_ARM64_REG_X0,
                "x1":     UC_ARM64_REG_X1,
                "x2":     UC_ARM64_REG_X2,
                "x3":     UC_ARM64_REG_X3,
                "x4":     UC_ARM64_REG_X4,
                "x5":     UC_ARM64_REG_X5,
                "x6":     UC_ARM64_REG_X6,
                "x7":     UC_ARM64_REG_X7,
                "x8":     UC_ARM64_REG_X8,
                "x9":     UC_ARM64_REG_X9,
                "x10":    UC_ARM64_REG_X10,
                "x11":    UC_ARM64_REG_X11,
                "x12":    UC_ARM64_REG_X12,
                "x13":    UC_ARM64_REG_X13,
                "x14":    UC_ARM64_REG_X14,
                "x15":    UC_ARM64_REG_X15,
                "x16":    UC_ARM64_REG_X16,
                "x17":    UC_ARM64_REG_X17,
                "x18":    UC_ARM64_REG_X18,
                "x19":    UC_ARM64_REG_X19,
                "x20":    UC_ARM64_REG_X20,
                "x21":    UC_ARM64_REG_X21,
                "x22":    UC_ARM64_REG_X22,
                "x23":    UC_ARM64_REG_X23,
                "x24":    UC_ARM64_REG_X24,
                "x25":    UC_ARM64_REG_X25,
                "x26":    UC_ARM64_REG_X26,
                "x27":    UC_ARM64_REG_X27,
                "x28":    UC_ARM64_REG_X28,
                "pc":     UC_ARM64_REG_PC,
                "sp":     UC_ARM64_REG_SP,
                "fp":     UC_ARM64_REG_FP,
                "lr":     UC_ARM64_REG_LR,
                "nzcv":   UC_ARM64_REG_NZCV,
                "cpsr": UC_ARM_REG_CPSR, 
            },
            "mips" : {
                "0" :     UC_MIPS_REG_ZERO,
                "at":     UC_MIPS_REG_AT,
                "v0":     UC_MIPS_REG_V0,
                "v1":     UC_MIPS_REG_V1,
                "a0":     UC_MIPS_REG_A0,
                "a1":     UC_MIPS_REG_A1,
                "a2":     UC_MIPS_REG_A2,
                "a3":     UC_MIPS_REG_A3,
                "t0":     UC_MIPS_REG_T0,
                "t1":     UC_MIPS_REG_T1,
                "t2":     UC_MIPS_REG_T2,
                "t3":     UC_MIPS_REG_T3,
                "t4":     UC_MIPS_REG_T4,
                "t5":     UC_MIPS_REG_T5,
                "t6":     UC_MIPS_REG_T6,
                "t7":     UC_MIPS_REG_T7,
                "t8":     UC_MIPS_REG_T8,
                "t9":     UC_MIPS_REG_T9,
                "s0":     UC_MIPS_REG_S0,
                "s1":     UC_MIPS_REG_S1,
                "s2":     UC_MIPS_REG_S2,    
                "s3":     UC_MIPS_REG_S3,
                "s4":     UC_MIPS_REG_S4,
                "s5":     UC_MIPS_REG_S5,
                "s6":     UC_MIPS_REG_S6,              
                "s7":     UC_MIPS_REG_S7,
                "s8":     UC_MIPS_REG_S8,  
                "k0":     UC_MIPS_REG_K0,
                "k1":     UC_MIPS_REG_K1,
                "gp":     UC_MIPS_REG_GP,
                "pc":     UC_MIPS_REG_PC,
                "sp":     UC_MIPS_REG_SP,
                "fp":     UC_MIPS_REG_FP,
                "ra":     UC_MIPS_REG_RA,
                "hi":     UC_MIPS_REG_HI,
                "lo":     UC_MIPS_REG_LO
            }
        }
        return registers[arch]  


    def get_common_regs(self):
        """
        get some common register
        REG_PC: IP
        REG_SP: stack pointer 
        REG_RA: return address (just like arm $lr and mips $ra)
        REG_ARGS: args 
        REG_RES: return value
        arch to uc_arch
        """

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
            self.size = 4
            self.pack_fmt = "<I"
            self.REG_PC = UC_MIPS_REG_PC
            self.REG_SP = UC_MIPS_REG_SP
            self.REG_RA = UC_MIPS_REG_RA
            self.REG_RES = [UC_MIPS_REG_V0, UC_MIPS_REG_V1,UC_MIPS_REG_V1]
            self.REG_ARGS = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]