from pwn import *


libc = ELF('./libc.so.0')


putsoffset = libc.symbols['puts']
systemoffset = libc.symbols['system']

for key , value in libc.symbols.items():
    print "symbols : {:<30} value :{}".format( key , hex(value))
