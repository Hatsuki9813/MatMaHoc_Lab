import ctypes
from ctypes import c_char_p
import sys
import os

# .so path
sopath=os.path.join(os.getcwd(),"digitalsignature.so")
 
# Load the shared library
sig = ctypes.CDLL(sopath, winmode=ctypes.DEFAULT_MODE) #winmode=0,1,2,3...
 
# Set up the prototype of the function
# All of them are strings (char*)


loadmess = sig.LoadMessage
loadmess.argtypes = [c_char_p]
loadmess.restype = c_char_p
genecdsa = sig.generateandsaveECCKey
genecdsa.argtypes = [c_char_p, c_char_p, c_char_p]
genecdsa.restype = None
signecdsa = sig.signMessage # call hashes funtion from shas.so;
signecdsa.argtypes = [c_char_p, c_char_p, c_char_p]
signecdsa.restype = ctypes.c_bool  # The function returns void
verifyecdsa = sig.verifyMessageSignature # call hashes funtion from shas.so;
verifyecdsa.argtypes = [c_char_p, c_char_p, c_char_p]
verifyecdsa.restype = ctypes.c_bool  # The function returns void

genrsasspss = sig.generateAndSaveRSAPSSKey
genrsasspss.argtypes = [c_char_p, c_char_p, c_char_p]
genrsasspss.restype = None

signrsasspss = sig.signMessage # call hashes funtion from shas.so;
signrsasspss.argtypes = [c_char_p, c_char_p, c_char_p]
signrsasspss.restype = ctypes.c_bool  

verifyrsasspss = sig.verifyMessageSignature # call hashes funtion from shas.so;
verifyrsasspss.argtypes = [c_char_p, c_char_p, c_char_p]
verifyrsasspss.restype = ctypes.c_bool 

def call_load(messPath):
    messPath = messPath.encode('utf-8')
    m = loadmess(messPath)
    return m
def call_gen_ecdsa(format, privateKeyPath, publicKeyPath):
    privateKeyPath = privateKeyPath.encode('utf-8')
    publicKeyPath = publicKeyPath.encode('utf-8')
    keyformat = format.encode('utf-8')
    genecdsa(keyformat, privateKeyPath,publicKeyPath)
    
def call_sign_ecdsa(privateKeyPath, messPath, signaturePath):
    # Convert Python strings to bytes, as ctypes works with bytes
    privateKeyPath = privateKeyPath.encode('utf-8')
    #messPath = messPath.encode('utf-8')
    signaturePath = signaturePath.encode('utf-8')
    # Call the C function
    k = signecdsa(privateKeyPath, messPath, signaturePath)
    return k
def call_verify_ecdsa(publicKeyPath, messPath, signaturePath):
    # Convert Python strings to bytes, as ctypes works with bytes
    publicKeyPath = publicKeyPath.encode('utf-8')
   # messPath = messPath.encode('utf-8')
    signaturePath = signaturePath.encode('utf-8')
    # Call the C function
    k = verifyecdsa(publicKeyPath, messPath, signaturePath)
    return k
def call_gen_rsasspss(format, privateKeyPath, publicKeyPath):
    privateKeyPath = privateKeyPath.encode('utf-8')
    publicKeyPath = publicKeyPath.encode('utf-8')
    keyformat = format.encode('utf-8')
    genrsasspss(keyformat, privateKeyPath,publicKeyPath)
def call_sign_rsasspss(privateKeyPath, messPath, signaturePath):
    # Convert Python strings to bytes, as ctypes works with bytes
    privateKeyPath = privateKeyPath.encode('utf-8')
    #messPath = messPath.encode('utf-8')
    signaturePath = signaturePath.encode('utf-8')
    # Call the C function
    k = signrsasspss(privateKeyPath, messPath, signaturePath)
    return k
def call_verify_rsasspss(publicKeyPath, messPath, signaturePath):
    # Convert Python strings to bytes, as ctypes works with bytes
    publicKeyPath = publicKeyPath.encode('utf-8')
   # messPath = messPath.encode('utf-8')
    signaturePath = signaturePath.encode('utf-8')
    # Call the C function
    k = verifyrsasspss(publicKeyPath, messPath, signaturePath)
    return k
if __name__ == "__main__":
 
    '''  if len(sys.argv)< 3:
        print(f"Usage: {sys.argv[0]} [sign|verify|genkey]  <other options>")
        sys.exit(1)
    
    if (sys.argv[1] == "genkey"):
        call_gen(sys.argv[2], sys.argv[3])
    if(sys.argv[1] == "sign" and sys.argv[2] == "file"):
        if len(sys.argv) != 6:
            print(f"Usage:  {sys.argv[0]} sign: <input mode> <private key file> <file: .txt> <signature file>")
            sys.exit(1)
    
        m = call_load(sys.argv[4])
        call_sign(sys.argv[3], m, sys.argv[5])

    if (sys.argv[1] == "sign" and sys.argv[2] == "input"):
        if len(sys.argv) != 6:
            print(f"Usage: {sys.argv[0]} sign: <input mode> <private key file> <message> <signature file>")
            sys.exit(1);
        call_sign( sys.argv[3], sys.argv[4], sys.argv[5]) 
    if (sys.argv[1] == "verify" and sys.argv[2] == "file"):
        if len(sys.argv) != 6: 
            print(f"Usage: {sys.argv[0]} verify: <input mode> <public key file> <file: .txt> <signature file> ")
            sys.exit(1);
        
        m = call_load(sys.argv[4]);
        call_verify(sys.argv[3], m, sys.argv[5])

    if  (sys.argv[1] == "verify" and sys.argv[2] == "input"):
    
        if len(sys.argv) != 6:
        
            print(f"Usage: {sys.argv[0]} verify:<input mode> <public key file> <message> <signature file>" )
            sys.exit(1);
        
        call_verify(sys.argv[3], sys.argv[4], sys.argv[5])'''
      

