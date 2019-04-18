# -*- coding: utf-8 -*-
"""
Created on Thu Mar 21 10:45:31 2019

@author: Christian Travina and William Jorgensen
"""

import os
import json
import base64
import os.path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.padding import MGF1 as uno
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
  
def generatePair():
    privKey = rsa.generate_private_key(publicExponent = 65537, keySize = 2048, backend=default_backend())
    pubKey = privKey.public_key()
    
    return pubKey, privKey

def keyValid():
    if(os.path.exists('C:\\Users\\Christian\\Documents\\CECS 378\\pubKey.pem') == False):
        pubKey, privKey = generatePair()
        
        privPem = privKey.private_bytes(encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm = serialization.NoEncryption())
        pubPem = pubKey.public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.SubjectPublicKeyInfo)
        
        os.makedirs('C:\\Users\\Christian\\Documents\\CECS 378')
        privFile = open('C:\\Users\\Christian\\Documents\\CECS 378\\privKey.pem', 'wb') #writes priv key to file as binary
        privFile.write(privPem)
        privFile.close()
        
        pubFile = open('C:\\Users\\Christian\\Documents\\CECS 378\\pubKey.pem', 'wb') #Writes pub key to file as binary
        pubFile.write(pubPem)
        pubFile.close()
        
        print('Public and Private keys are generated')
        

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


def MyRSAEncrypt(filepath, rsa_pub_path):
    cipher, IV, tag, key, ext, HMACKey = MyfileEncryptMAC(filepath)
    
    newKey = key+HMACKey #Key concat
    
    with open(rsa_pub_path, 'rb') as pub_file: #opens up file with public key
        pub = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    pub_file.close()  
    
    #key creates encoded key
    keyEncRSA = pub.encrypt(newKey, padding.OAEP(maskGen = MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(), label = None))
#    signature = 
    
    
    return (cipher, IV, tag, keyEncRSA, ext) 


def MyRSADecrypt(filepath, cipher, IV, tag, keyEncRSA, ext, RSA_privkey_filepath):
    
    with open(RSA_privkey_filepath, 'rb') as pem_file: #opens up file using pem private key and *serialization
        pubPem = serialization.load_pem_private_key(pem_file.read(), password = None, backend=default_backend())
    
    pem_file.close()
    
    key = pem.decrypt(key_cipher, padding.OAEP(maskGen = MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA1(), label = None))
    k = key[:32]
    hkey = key[-32:] #need to fix
    
    m = MydecryptMAC(cipher, keyEncRSA, IV, tag, hkey)
    
    return m

    
   
        
    

def main():
    
    filepath = "C:\\Users\\Christian\\Documents\\CECS 378\\yellow.jpg"
    cipher, IV, tag, key, ext, HMACKey = MyfileEncryptMAC(filepath)
    MyfileDecryptMAC(filepath, cipher, key, IV, tag, HMACKey, ext)
    
    f = Image.open('yellow.jpg')
    f.show()
    f.close()
    
    
main()    