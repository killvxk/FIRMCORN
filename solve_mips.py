from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/dir859/" , "cgibin")

run_start_addr = 0x0040F7DC            
run_end_addr = 0x0040F8DC

# hook_func = [0x00400460]
# fuzz_target = Fuzzer(5 , "a"*256 , hook_func)
# fc.add_fuzz(fuzz_target)
# strcpy_addr = 0x00400470 
# skip_list = [0x0004005C8  , 0x004005F7]

dbg_list = [0x0040F88C , 0x0040F8D0]
fc.show_debug_info(dbg_list)

# fc.hookcode.func_skip(skip_list)
trace_start_addr = 0x00420080 
trace_end_addr = 0x0042008C  
fc.set_trace(trace_start_addr, trace_end_addr ) 
fc.start_run(run_start_addr , run_end_addr )
