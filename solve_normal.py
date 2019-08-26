from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/UnicornContext_20190309_193002/")

'''
def hook_code(mu, address, size, user_data):
    instr = fc.mem_read(address , size)
    # print ("0x%x %s" % (address ,   disasm(instr).replace("0:" , "") ) )
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

print_addr = 0x0400400    
skip_list = [0x400534 ]
# fc.hook_add(UC_HOOK_CODE , hook_code)
fc.hookcode.func_alt( print_addr , fc.funcemu._printf , 2)
fc.set_trace(0x00400526, 0x040052F)
# fc.hookcode.func_skip(skip_list)
fc.start_run( 0x00400526  , 0x0000040053F )
'''

scanf_addr = 0x04004E0 
strcpy_addr = 0x04004B0 
skip_list = [0x00004005FE , 0x040064A , 0x0040063F ]

fc.hookcode.func_alt(scanf_addr , fc.funcemu._scanf  , 2)
fc.hookcode.func_alt(strcpy_addr , fc.funcemu._strcpy  , 2)
fc.hookcode.func_skip(skip_list)
# fc.set_trace(0x000004005F6, 0x0000400607 )
run_start_addr = 0x00004005F6    
run_end_addr = 0x0400650
fc.start_run(run_start_addr , run_end_addr)
