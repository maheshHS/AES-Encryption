#!/usr/bin/python3
import sys
import argparse
from Crypto import Random
from Crypto.Cipher import AES
import os
import base64
import hashlib

class Decryptor:
    def __init__(self, password):
        self.key = self.setPassword(password)

    def setPassword(self ,password):
        return hashlib.sha256(password.encode("utf-8")).digest()

    def decrypt(self, ciphertxt, key):
        iv = ciphertxt[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        text = cipher.decrypt(ciphertxt[AES.block_size:])
        return text.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as f:
            ciphertxt = f.read()
        decrypted_content = self.decrypt(ciphertxt, self.key)
        with open( file_name[:-4], 'wb') as f:
            f.write(decrypted_content)
        print("Decrypted : " + file_name)
        os.remove(file_name)
    

if __name__ == '__main__':
    ArgParser = argparse.ArgumentParser()
    ArgParser.add_argument("-P", "--password", required=True, help="password")
    ArgParser.add_argument("-f", "--files",nargs='+', required=True, help="filenames")
    args = vars(ArgParser.parse_args())
    decryptor = Decryptor(args['password'])
    for f in args['files']:
        decryptor.decrypt_file(f)
    

