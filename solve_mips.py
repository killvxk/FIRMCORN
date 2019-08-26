from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/dir859/")
# hook_func = [0x00400460]
# fuzz_target = FuzzTarget(5 , "a"*256 , hook_func)
# fc.add_fuzz(fuzz_target)
strcpy_addr = 0x00400470 
# skip_list = [0x0004005C8  , 0x004005F7]


memset_addr = 0x0043554C
fc.hookcode.func_alt(strcpy_addr , fc.funcemu._strcpy  , 2)
fc.hookcode.func_alt(memset_addr , fc.funcemu._memset  , 2)
# fc.hookcode.func_skip(skip_list)

run_start_addr = 0x0040F7DC          
run_end_addr = 0x0040F920       
fc.set_trace(run_start_addr, run_end_addr )
fc.start_run(run_start_addr , run_end_addr )
