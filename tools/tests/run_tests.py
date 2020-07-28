#!/usr/bin/env python
"""
Test Tool

This tool will run a series of tests to ensure basic interoperability between the various python tools. 
As of now, it will NOT test communication between the bootloader and fw_update, so that needs to be done manually. 
"""

import argparse
import os
import pathlib
import shutil
import subprocess
import struct

FILE_DIR = pathlib.Path(__file__).parent.absolute()

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
# from bl_build import *
# from fw_protect import *

res_counter = 0
def log_result(msg, res=0): 
    global res_counter
    res_counter += 1
    with open('tests/results.txt', 'a') as file:
        char = '\u2705' if res is 0 else '\u274c'
        file.write(f'\n{char} [{res_counter}] {msg}')

# AES decryption algorithm 
def aes_decrypt(nonce_var, metadata, cipher_text, tag_var, key, chunk):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_var)
        cipher.update(metadata)
#         cipher.verify(tag_var)
        plaintext = cipher.decrypt_and_verify(cipher_text, tag_var)
#         print(type(plaintext))
    #         result = unpad(plaintext, 16)
        return plaintext.decode('utf-8')
    except ValueError:
        print(f'\x1b[1m\x1b[31m[AES-D] ValueError when attempting to decrypt chunk {chunk}. \x1b[0m')
        log_result(f'Failed to decrypt and verify chunk {chunk}', 1)
        return ''
    
def verify_rsa(ciphertext, key, signature, metadata):
    try:
        h = SHA256.new(ciphertext + metadata)
        print(f'hash{h.hexdigest()}')
        pkcs1_15.new(key).verify(h, signature)
        print("yay")
        return 1
    except ValueError:
        print("Fail. Wrong Value")
        return 0 
        
if __name__ == '__main__':
    print('\x1b[92mC.I.A. Test Script\x1b[0m')
    print('\x1b[96mv0.1 // 7.22.20\x1b[0m')
    print('\n')
    
    print('(i) See results.txt for a summary of test results. \n')
    os.chdir(FILE_DIR / '..') # Exit tests directory
    
    with open('tests/results.txt', 'w') as file: # Create a new file and overwrite any existing content
        file.write('C.I.A. Test Suite\n')
    
    # Test #1: Run bl_build.py to generate a fresh build, and ensure that it runs correctly
    print('\x1b[46mTest 1: bl_build.py should run without errors\x1b[0m')
    print('\x1b[96mRunning bl_build.py...\x1b[0m')
    status = subprocess.call('python bl_build.py', shell=True)
    
    log_result('bl_build.py runs without any errors', status)
    if status == 0: 
        print(f'\x1b[92mDone. Process returned status 0\x1b[0m')
    else: 
        print('\x1b[1m\x1b[31m[Test 1] Recieved a non-zero status code, aborting. \x1b[0m')
        os._exit(os.EX_OK) 
    
    # Test #2: Test fw_protect.py against a dummy file to ensure it runs without errors
    print('\n\x1b[46mTest 2: fw_protect.py should run without errors\x1b[0m')
    print('\x1b[96mRunning fw_protect.py...\x1b[0m')
    status = subprocess.call('python fw_protect.py --infile tests/testfirmware.bin --outfile tests/testout.blob --version 4 --message "test works"', shell=True)
    
    log_result('fw_protect.py runs without any errors', status)
    if status == 0: 
        print(f'\x1b[92mDone. Process returned status 0\x1b[0m')
    else: 
        print('\x1b[1m\x1b[31m[Test 2] Recieved a non-zero status code, aborting. \x1b[0m')
        os._exit(os.EX_OK) 
    
    # Test #3: Decrypt the dummy file created by fw_protect.py and see if the data is correct
    print('\n\x1b[46mTest 3: fw_protect.py should correctly encrypt the firmware\x1b[0m')
    
    with open('secret_build_output.txt', 'rb') as fp:
        secrets = fp.read()
    aes_key = secrets[0:16]
    print(aes_key.hex())
    rsa_key = RSA.import_key(secrets[16:])
    
    decrypted = ''
    with open('tests/testout.blob', 'rb') as fp: 
        encrypted = fp.read()
    
    curChunk = 0
    print(f'> Size: {len(encrypted)}')
    while len(encrypted) > 0: 
        curChunk += 1
        print('Now on: Chunk', curChunk)
        chunk = encrypted[0:1320]
        encrypted = encrypted[1320:]
        
        metadata = chunk[0:8]
        chunk_length = struct.unpack("<hhhh", metadata)[3]
        if chunk_length % 16 != 0: # account for padding
            chunk_length += 16 - (chunk_length % 16)
        chunk = chunk[0:chunk_length + 296]
        print(f'> Metadata: {metadata}')
        print(f'> Chunk Length: {chunk_length}')
        
        nonce = chunk[8:24]
        print(f'> Nonce: {nonce.hex()}')
        tag = chunk[24:40]
        print(f'> Tag: {tag.hex()}')
        rsasig = chunk[40:296]
        print(f'> rsa hex: {rsasig.hex()}')
        print(rsa_key.n.to_bytes(256, 'big').hex())
        print(rsa_key.e.to_bytes(3, 'big').hex())
        ciphertext = chunk[296:]
#         print(f'> cipher: {ciphertext}')
        print(f'> cipher hex: {ciphertext.hex()}')
        print(f'> cipherlen: {len(ciphertext)}')
        
        out = aes_decrypt(nonce, metadata, ciphertext, tag, aes_key, curChunk)
        verify_rsa(ciphertext, rsa_key, rsasig, metadata)
        if out != '':
            decrypted += out
            print('> Successfully decrypted')
        else: 
            print('> Decryption failed')
    print('\nAll chunks read. Checking data against original...')
    with open('tests/testfirmware.bin', 'r') as fp: 
        expected_bin = fp.read()
#     print('decrypted result:', decrypted)
#     print('expected:', expected_bin)
    if decrypted[:len(expected_bin)] == expected_bin: 
        log_result('fw_protect.py encrypts contents correctly', 0)
        print(f'\x1b[92mDecrypted firmware binary matches original binary\x1b[0m')
    else: 
        log_result('fw_protect.py encrypts contents correctly', 1)
        print(f'\x1b[1m\x1b[31mDecrypted firmware binary does NOT match original binary\x1b[0m')
        print(f'\x1b[1m\x1b[31mTest 3 failed, exiting\x1b[0m')
        os._exit(os.EX_OK) 
    
    # Test #4: Run fw_protect.py against the real firmware binary
#     print('\n\x1b[46mTest 3: Running fw_protect.py against a production binary\x1b[0m')
#     print('\x1b[96mRunning fw_protect.py...\x1b[0m')
#     status = subprocess.call('python fw_protect.py --infile ../firmware/firmware/gcc/main.bin --outfile test_firmwareblob.blob --version 4 --message "test works"', shell=True)

    print('')
    print(f'\x1b[92m=======================\x1b[0m')
    print(f'\x1b[92m| ALL TESTS PASSED 🎉  |\x1b[0m')
    print(f'\x1b[92m=======================\x1b[0m')