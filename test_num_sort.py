from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/num_sort/" , "num_sort" , "libc.so.6" )
run_start_addr = 0x00400786       
run_end_addr = 0x00000400B83         

fuzz_target = Fuzzer(5 , "a"*200 )
# fc.add_fuzz(fuzz_target)

show_info_list = [ 0x004007db ]
fc.show_debug_info(show_info_list)
skip_list = [0x0400B66 , 0x000400B6A , 0x040079F , 0x0400A89 , 0x0400AEE ,0x0400B0E]
fc.func_skip(skip_list)
# func_list = ['strdup' , "memmove" , "memcpy" , "free" ,"snprintf" , "socket" , "fcntl" , "connect" , "send", "close" , "free"]
func_list = ["rand"]
trace_start_addr = 0x00400786 
trace_end_addr = 0x00000400B83
fc.add_func(func_list)    
# fc.set_trace(trace_start_addr, trace_end_addr ) 
fc.start_run(run_start_addr , run_end_addr )
