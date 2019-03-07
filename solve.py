from firmcorn import *
from pwn import *




fc = Firmcorn()
fc.loadContext("/home/b1ngo/firmcorn/UnicornContext_20190305_160238/")



def hook_code(mu, address, size, user_data):
    instr = fc.mem_read(address , size)
    # print ("0x%x %s" % (address ,   disasm(instr).replace("0:" , "") ) )
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))


fc.setHook(UC_HOOK_CODE , hook_code)
fc.startRun(0x0000400F11,  0x0400F1C )

