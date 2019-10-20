from firmcorn import *


fc = Firmcorn()
fc.load_context("/home/b1ngo/Firmcorn/dump/loop_output/" , "./evaluation/loop_output" , "libc.so.6" )
run_start_addr = 0x000400626
run_end_addr = 0x00000400664

fuzz_target = Fuzzer(5 , "a"*200 )
# fc.add_fuzz(fuzz_target)

show_info_list = [ 0x004007db ]
fc.show_debug_info(show_info_list)
skip_list = [0x0000400646 , 0x00400650 , 0x40064B ]
fc.func_skip(skip_list)
# func_list = ['strdup' , "memmove" , "memcpy" , "free" ,"snprintf" , "socket" , "fcntl" , "connect" , "send", "close" , "free"]
# func_list = ["rand"]
trace_start_addr = 0x000400626 
trace_end_addr = 0x00000400664
# fc.add_func(func_list)    
# fc.set_trace(trace_start_addr, trace_end_addr ) 
fc.start_run(run_start_addr , run_end_addr )
