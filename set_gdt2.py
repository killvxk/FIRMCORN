#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
from struct import pack

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1 

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_EXEC = 0x8
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

CODE = 'insert code here'.encode('hex') 

def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret

def create_gdt_entry(base, limit, access, flags):

    to_ret = limit & 0xffff;
    to_ret |= (base & 0xffffff) << 16;
    to_ret |= (access & 0xff) << 40;
    to_ret |= ((limit >> 16) & 0xf) << 48;
    to_ret |= (flags & 0xff) << 52;
    to_ret |= ((base >> 24) & 0xff) << 56;
    return pack('<Q',to_ret)

def hook_mem_read(uc, type, addr,*args):
    print(hex(addr))
    return False

def write_gdt(uc, gdt, mem):
    for idx, value in enumerate(gdt):
        offset = idx * GDT_ENTRY_SIZE
        uc.mem_write(mem + offset, value)

CODE_ADDR = 0x40000
CODE_SIZE = 0x1000

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

GS_SEGMENT_ADDR = 0x5000
GS_SEGMENT_SIZE = 0x1000



uc = Uc(UC_ARCH_X86, UC_MODE_32 + UC_MODE_LITTLE_ENDIAN)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read)

uc.mem_map(GDT_ADDR, GDT_LIMIT)
uc.mem_map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)
uc.mem_map(CODE_ADDR, CODE_SIZE)

uc.mem_write(CODE_ADDR, CODE)

gdt = [create_gdt_entry(0,0,0,0) for i in range(31)]
gdt[15] = create_gdt_entry(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
gdt[16] = create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment
gdt[17] = create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment
gdt[18] = create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment



uc = Uc(UC_ARCH_X86, UC_MODE_32 + UC_MODE_LITTLE_ENDIAN)
write_gdt(uc, gdt, GDT_ADDR)
uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt) * GDT_ENTRY_SIZE-1, 0x0))

selector = create_selector(15, S_GDT | S_PRIV_3)
uc.reg_write(UC_X86_REG_GS, selector)

selector = create_selector(16, S_GDT | S_PRIV_3)
uc.reg_write(UC_X86_REG_DS, selector)

selector = create_selector(17, S_GDT | S_PRIV_3)
uc.reg_write(UC_X86_REG_CS, selector)

selector = create_selector(18, S_GDT | S_PRIV_0)
uc.reg_write(UC_X86_REG_SS, selector)

uc.emu_start(CODE_ADDR, CODE_ADDR+len(CODE))
