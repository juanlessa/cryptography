# cryptography

## symmetricCrypt.py
Program to encrypt or decrypt files according an algorithm name ("3DES", "AES-128" or "ChaCha20" and an cipher mode ("ECB", "CFB", "CBC", "OFB").  
This program has a CLI and you can see the usage:  
    $ python3 symmetricCrypt.py -h  
You also can import this file to use they methods.
### symmetricCrypt.py methods:
* encrypt -> encrypt a file according algorithm and cipher mode specified
* decrypt -> decrypt a file according algorithm and cipher mode specified
* generate_key -> generate key using PBKDF derivation
* addPadding -> add padding to a message block according to a chosen cryptographic algorithm
* removePadding -> remove padding to a message block, the length of "messageBlock" is used to know the cryptographic algorithm 
## hashFunction.py
Program to hash a file.
This program has a CLI and you can see the usage:  
    $ python3 hashFunction.py -h  
You also can import this file to use they methods.
### hashFunction.py methods:
* hash -> hash a file using one chosen hash function
