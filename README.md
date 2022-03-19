# Learning With Errors Proof of Concept
*This has only been tested on Ubuntu 20.04 LTS, mileage on other operating systems may vary* 
## Dependancies
* pycryptodome
* pickle
## Project Structure

To see how the encryption works, look in ``LWElib.sage``. This is where the real work is done.  

If you were, for example a Professor wishing to quickly check that the encryption was implemented correctly, this is the best place to look, especially at the LWE class members ``generate``, ``encrypt``, and ``decrypt``.  

Other than that, ``LWElib.py`` is just ``LWElib.sage`` after running it through the sage preparser.  
``LWEconsole`` is a wrapper around ``LWElib`` that creates a commandline utility for verifying the correctness of the encryption.  
No guarantee that the console app works perfectly. 
## Guide

To test encryption and decryption:

```
./LWElib.py "Hello world"
```

To use the console app:

Generate keys:
```
./LWEconsole -g 
```

Encrypt:
```
./LWEconsole -e -m "Message to encrypt
```

Decrypt:
```
./LWEconsole -d 
```

Display help message:
```
./LWEconsole -h 
```
