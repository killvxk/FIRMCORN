from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/dir859/" , "cgibin" , "libc.so.0" )
# fc.load_library("")
# fc.load_library("ld-uClibc.so.0")

run_start_addr = 0x0040F7DC
run_end_addr = 0x0040F8EC

# hook_func = [0x00400460]
# fuzz_target = Fuzzer(5 , "a"*256 , hook_func)
# fc.add_fuzz(fuzz_target)
# strcpy_addr = 0x00400470 
# skip_list = [0x0004005C8  , 0x004005F7]

# dbg_list = [0x41c2b8 , 0x41c2bc]
# fc.show_debug_info(dbg_list)

# # fc.hookcode.func_skip(skip_list)
func_list = ['strdup' , "memmove" , "memcpy" , "free" ,"snprintf" , "socket" , "fcntl" , "connect" , "send", "close"]
trace_start_addr = 0x76743670 
trace_end_addr = 0x767436c0  
fc.add_func(func_list)
fc.set_trace(0x0040F7DC, run_end_addr ) 
fc.start_run(run_start_addr , run_end_addr )
