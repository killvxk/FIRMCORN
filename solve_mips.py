from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/dir859/" , "cgibin" , "libc.so.0" )
run_start_addr = 0x0040F7DC
run_end_addr = 0x040F91C  

fuzz_target = Fuzzer(5 , "a"*200 )
fc.add_fuzz(fuzz_target)

show_info_list = [0x040F918]
fc.show_debug_info(show_info_list)

# fc.func_skip(skip_list)
# func_list = ['strdup' , "memmove" , "memcpy" , "free" ,"snprintf" , "socket" , "fcntl" , "connect" , "send", "close" , "free"]
trace_start_addr = 0x0040F7DC 
trace_end_addr = 0x0040F914  
# fc.add_func(func_list)
# fc.set_trace(trace_start_addr, trace_end_addr ) 
fc.start_run(run_start_addr , run_end_addr )
