import ctypes
from ctypes import c_char_p
import sys
import os

# .so path
sub_dir = "4.1_HashFunctionandUI"
sopath=os.path.join(os.getcwd(), sub_dir,"seperatehash.so")
print(sopath)
 