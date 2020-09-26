#!/usr/bin/python3
import sys
import argparse
from Crypto import Random
from Crypto.Cipher import AES
import os
import base64
import hashlib

class Encryptor:
    def __init__(self, password):
        self.key = self.setPassword(password)

    def setPassword(self ,password):
        return hashlib.sha256(password.encode("utf-8")).digest()

    def padding(self, s):
        return s+b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key ):
        message = self.padding(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as f:
            text = f.read()
        enc = self.encrypt(text, self.key)
        with open(file_name + ".enc", 'wb') as f:
            f.write(enc)
        print("Encrypted : " + file_name)
        os.remove(file_name)

if __name__ == '__main__':
    ArgParser = argparse.ArgumentParser()
    ArgParser.add_argument("-P", "--password", required=True, help="password")
    ArgParser.add_argument("-f", "--files",nargs='+', required=True, help="filenames")
    args = vars(ArgParser.parse_args())
    encryptor = Encryptor(args['password'])
    for f in args['files']:
        encryptor.encrypt_file(f)
    

