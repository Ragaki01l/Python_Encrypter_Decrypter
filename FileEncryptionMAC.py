# -*- coding: utf-8 -*-
"""
Created on Thu Mar  7 20:20:17 2019

@author: Christian Travina and William Jorgensen
"""

import os
import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import io
from PIL import Image




def MyencryptMAC(message, key, HMACKey):
    
    if(len(key) < 32): #Error if key is too short
        
            return "Error, the length of key is short."
        
    if(len(HMACKey) < 32): 
            return "Error, the length of HMACKey is short."
        
    backend = default_backend()
    IV = os.urandom(16) #Generates the IV
    
    padder = padding.PKCS7(256).padder() #Ensures it fills up the entire block
    message = padder.update(message) #Message w/ padding
    message += padder.finalize()
    
    c =  Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend) #Initializes c Cipher
    encryptor = c.encryptor() #Encrypts using c cipher
    ct = encryptor.update(message) + encryptor.finalize() 
    
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = backend)
    h.update(ct)
    t = h.finalize()

    return ct, IV, t


def MydecryptMAC(cipher, key, iv, tag, HMACKey): 
   
   backend = default_backend()
  
   
   checkTag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=backend)
   checkTag.update(cipher)
   
   try:
       checkTag.verify(tag)
       
       c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
       decryptor = c.decryptor()
       message = decryptor.update(cipher) + decryptor.finalize()
    
       unpadder = padding.PKCS7(256).unpadder() #Removes padding to find message
       m = unpadder.update(message)
       m = m + unpadder.finalize()
       
       return m 
   
   except InvalidSignature:
       return "Tag is invalid."
  



def MyfileEncryptMAC(filepath):
    
    f = open(filepath, "rb")
    content = f.read()
    f.close()
   
    ext = os.path.splitext(filepath)
    ext = ext[1]
    key = os.urandom(32)
    HMACKey = os.urandom(32)
    
    C, iv, tag = MyencryptMAC(content, key, HMACKey)
    f = open(filepath, "wb")
    f.write(C)
    f.close()
    return  C, iv, tag, key, ext, HMACKey




def MyfileDecryptMAC(filepath, cipher, key, iv, tag, HMACKey, ext):
    
    pt = MydecryptMAC(cipher, key, iv, tag, HMACKey)
    f = open(filepath, 'wb')
    f.write(pt)
    f.close()
    
    return pt
    

def main():
    
    filepath = "C:\\Users\\Christian\\Documents\\CECS 378\\yellow.jpg"
    cipher, IV, tag, key, ext, HMACKey = MyfileEncryptMAC(filepath)
    MyfileDecryptMAC(filepath, cipher, key, IV, tag, HMACKey, ext)
    
    f = Image.open('yellow.jpg')
    f.show()
    f.close()
    
    
main()    