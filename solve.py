from firmcorn import *
from pwn import *




fc = Firmcorn()
fc.load_context("/home/b1ngo/firmcorn/UnicornContext_20190308_231949/")


def hook_code(mu, address, size, user_data):
    instr = fc.mem_read(address , size)
    # print ("0x%x %s" % (address ,   disasm(instr).replace("0:" , "") ) )
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

def myprint(uc, out, args):
    print("this is hook output: %d" % args[1])
    return 0


print_addr = 0x0400400    

# fc.hook_add(UC_HOOK_CODE , hook_code)
fc.hc.func_alt( print_addr , myprint , 2)
fc.start_run( 0x00400526  , 0x0000040053F )

