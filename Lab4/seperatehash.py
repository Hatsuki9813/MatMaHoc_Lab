import ctypes
from ctypes import c_char_p
import sys
import os

# .so path
sopath=os.path.join(os.getcwd(), "seperatehash.so")
# Load the shared library
sig = ctypes.CDLL(sopath, winmode=ctypes.DEFAULT_MODE) #winmode=0,1,2,3...
 
# Set up the prototype of the function
# All of them are strings (char*)

sha224 = sig.sha224
sha224.argtypes = [c_char_p, c_char_p, c_char_p]
sha224.restype = c_char_p
sha256 = sig.sha256
sha256.argtypes = [c_char_p, c_char_p,  c_char_p]
sha256.restype =  c_char_p
sha384 = sig.sha384
sha384.argtypes = [c_char_p, c_char_p,  c_char_p]
sha384.restype =  c_char_p
sha512 = sig.sha512
sha512.argtypes = [c_char_p, c_char_p,  c_char_p]
sha512.restype =  c_char_p
sha3_224 = sig.SHA3_224
sha3_224.argtypes = [c_char_p, c_char_p,  c_char_p]
sha3_224.restype =  c_char_p
sha3_256 = sig.SHA3_256
sha3_256.argtypes = [c_char_p, c_char_p,  c_char_p]
sha3_256.restype =  c_char_p
sha3_384 = sig.SHA3_384
sha3_384.argtypes = [c_char_p, c_char_p,  c_char_p]
sha3_384.restype =  c_char_p
sha3_512 = sig.SHA3_512
sha3_512.argtypes = [c_char_p, c_char_p,  c_char_p]
sha3_512.restype =  c_char_p
shake128 = sig.shake128
shake128.argtypes = [c_char_p, c_char_p,  c_char_p,  c_char_p]
shake128.restype =  c_char_p
shake256 = sig.shake256
shake256.argtypes = [c_char_p, c_char_p,  c_char_p,  c_char_p]
shake256.restype =  c_char_p
def call_sha224(input,inputfile ,outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha224(input, inputfile, outpufile)
    return m
def call_sha256(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha256(input, inputfile, outpufile)
    return m

def call_sha384(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha384(input, inputfile, outpufile)
    return m
def call_sha512(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha512(input, inputfile, outpufile)
    return m
def call_sha3_224(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha3_224(input, inputfile, outpufile)
    return m
def call_sha3_256(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha3_256(input, inputfile, outpufile)
    return m
def call_sha3_384(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha3_384(input, inputfile, outpufile)
    return m
def call_sha3_512(input,inputfile, outpufile):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    m = sha3_512(input, inputfile, outpufile)
    return m
def call_shake128(input,inputfile ,outpufile, length):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    length = length.encode('utf-8')
    m = shake128(input, inputfile, outpufile, length)
    return m
def call_shake256(input,inputfile, outpufile, length):
    input = input.encode('utf-8')
    inputfile = inputfile.encode('utf-8')
    outpufile = outpufile.encode('utf-8')
    length = length.encode('utf-8')
    m = shake256(input, inputfile, outpufile, length)
    return m

if __name__ == "__main__":
    print("soasda")
    call_sha224("0", "test.txt", "output.txt")
'''if (sys.argv[1] == "SHA224"):
        call_sha224(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHA256"):
        call_sha256(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHA384"):
       call_sha384(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHA512"):
       call_sha512(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHA3-224"):
        call_sha3_224(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHA3-256"):
        call_sha3_256(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHA3-384"):
        call_sha3_384(sys.argv[2], sys.argv[3], sys.argv[4])
    if(sys.argv[1] == "SHA3-512"):
        call_sha3_512(sys.argv[2], sys.argv[3], sys.argv[4])
    if (sys.argv[1] == "SHAKE128"):
        call_shake128(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    if (sys.argv[1] == "SHAKE256"):
        call_shake256(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])'''
    