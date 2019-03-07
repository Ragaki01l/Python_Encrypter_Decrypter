# -*- coding: utf-8 -*-
"""
Created on Tue Mar  5 12:41:04 2019

@author: Christian Travina and William Jorgensen
"""

import os
import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import io
from PIL import Image


def Myencrypt(message, key):

	if(len(key) < 32): #Error if key is too short
        
            return "Error, the length of key is short."

	backend = default_backend()
	IV = os.urandom(16) #Generates the IV
    
	padder = padding.PKCS7(256).padder() #Ensures it fills up the entire block
	message = padder.update(message) #Message w/ padding
	message += padder.finalize()
    
	c =  Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend) #Initializes c Cipher
	encryptor = c.encryptor() #Encrypts using c cipher
	ct = encryptor.update(message) + encryptor.finalize() 
    

	return ct, IV

def Mydecrypt(cipher, key, iv):

	backend = default_backend()
	c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = c.decryptor()
	message = decryptor.update(cipher) + decryptor.finalize()
    
	unpadder = padding.PKCS7(256).unpadder() #Removes padding to find message
	m = unpadder.update(message)
	m = m + unpadder.finalize()
    
	return m



def MyfileEncrypt(filepath):
    
    f = open(filepath, "rb")
    content = f.read()
    f.close()
   
    ext = os.path.splitext(filepath)
    ext = ext[1]
    key = os.urandom(32)
    
    C, iv = Myencrypt(content, key)
    f = open(filepath, "wb")
    f.write(C)
    f.close()
    return  C, iv, key, ext



def MyfileDecrypt(filepath, cipher, key, iv):
    pt = Mydecrypt(cipher, key, iv)
    
    f = open(filepath, 'wb')
    f.write(pt)
    f.close()
    
    return pt

def main():
    
    filepath = "C:\\Users\\Christian\\Documents\\CECS 378\\minion.jpg"
    cipher, IV, key, ext = MyfileEncrypt(filepath)
    MyfileDecrypt(filepath, cipher, key, IV)
    
    f = Image.open('minion.jpg')
    f.show()
    f.close()
    
    
main()    