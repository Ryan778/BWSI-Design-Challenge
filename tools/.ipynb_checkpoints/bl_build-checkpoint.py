#!/usr/bin/env python
"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
<<<<<<< HEAD

FILE_DIR = pathlib.Path(__file__).parent.absolute()

=======
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

FILE_DIR = pathlib.Path(__file__).parent.absolute()

def generate_keys(): 
    """
    Generates a 2048 bit RSA public/private key pair and a 128 bit AES key. 
    The AES key will be written directly into bootloader.c in the format "char AES_KEY = {0x00, ...}"
    Return:
        None
    """
    newkey = get_random_bytes(16)

    # Change into directory containing bootloader source.
    bldir = FILE_DIR / '..' / 'bootloader' / 'src'
    os.chdir(bldir)
    with open('bootloader.c', 'r') as file:
        bootloader = file.read()
        if bootloader[0:12] == 'char AES_KEY': # Check if a key is already present from a previous build
            bootloader = bootloader[bootloader.index('\n')+1:] # Remove old key
        byteout = ''
        for i in range(16): 
            byteout += ', 0x' + newkey[i:i+1].hex() # Write the bytes in hex form for C implementation (0xXX, etc.)
        byteout = byteout[2:]
        file.close()
    with open('bootloader.c', 'w') as file:
        file.write('char AES_KEY[16] = {'+byteout+'};\n') # Write key into bootloader
        file.close()
    with open('bootloader.c', 'a') as file:
        file.write(bootloader) # Append rest of the bootloader code back on
        file.close()
    
    # Change into directory containing tools
    os.chdir(FILE_DIR)
    with open('secret_build_output.txt', 'wb') as file: 
        file.write(newkey) # Write AES key into secret file as binary bytes (to be used by fw_protect)
>>>>>>> c64f90e9c2a9a3c6d40832d6f0c855752b12a962

def copy_initial_firmware(binary_path):
    """
    Copy the initial firmware binary to the bootloader build directory
    Return:
        None
    """
    # Change into directory containing tools
    os.chdir(FILE_DIR)
    bootloader = FILE_DIR / '..' / 'bootloader'
    shutil.copy(binary_path, bootloader / 'src' / 'firmware.bin')

<<<<<<< HEAD

=======
>>>>>>> c64f90e9c2a9a3c6d40832d6f0c855752b12a962
def make_bootloader():
    """
    Build the bootloader from source.

    Return:
        True if successful, False otherwise.
    """
    # Change into directory containing bootloader.
    bootloader = FILE_DIR / '..' / 'bootloader'
    os.chdir(bootloader)

    subprocess.call('make clean', shell=True)
    status = subprocess.call('make')

    # Return True if make returned 0, otherwise return False.
    return (status == 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootloader Build Tool')
    parser.add_argument("--initial-firmware", help="Path to the the firmware binary.", default=None)
    args = parser.parse_args()
    if args.initial_firmware is None:
        binary_path = FILE_DIR / '..' / 'firmware' / 'firmware' / 'gcc' / 'main.bin'
    else:
        binary_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(binary_path):
        raise FileNotFoundError(
            "ERROR: {} does not exist or is not a file. You may have to call \"make\" in the firmware directory.".format(
                binary_path))

    copy_initial_firmware(binary_path)
<<<<<<< HEAD
=======
    generate_keys()
>>>>>>> c64f90e9c2a9a3c6d40832d6f0c855752b12a962
    make_bootloader()
