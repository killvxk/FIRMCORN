from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/aes/" , "./evaluation/aes" , "libc.so.6" )
run_start_addr = 0x000400E08        
run_end_addr = 0x00400EB4         

fuzz_target = Fuzzer(5 , "a"*200 )
# fc.add_fuzz(fuzz_target)

# show_info_list = [ 0x004007db ]
# fc.show_debug_info(show_info_list)
# skip_list = [0x00401112 , 0x0000401318]   
# fc.func_skip(skip_list)
# func_list = ['strdup' , "memmove" , "memcpy" , "free" ,"snprintf" , "socket" , "fcntl" , "connect" , "send", "close" , "free"]
# func_list = ["rand"]
trace_start_addr = 0x000400E08 
trace_end_addr = 0x00400EB4
# fc.add_func(func_list)    
fc.set_trace(trace_start_addr, trace_end_addr ) 
fc.start_run(run_start_addr , run_end_addr )
