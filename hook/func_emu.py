import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib
# from pwn import * 
# import unicorn

# Unicorn imports
# require unicorn moudle
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


# there are simulation of common function
# once you 