import subprocess
out_bytes = subprocess.check_output(['gdbserver' , '127.0.0.1:1234' , "1"])
out_text = out_bytes.decode('utf-8')
print out_bytes