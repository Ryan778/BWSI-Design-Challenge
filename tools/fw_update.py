#!/usr/bin/env python
"""
Firmware Updater Tool

1. Initializes update mode by sending and receiving a 'U'. 
   Sends the metadata to the bootloader.

2. Takes each packet from the firmware blob, splits it into 16 byte frames, and 
   sends each frame to the bootloader, and waits for an "OK" message after each 
   frame.
    - The OK message is just a zero
    - The ERROR message is just a one

A frame consists of two sections:
    - Two bytes for the length of the data section
    - A data section of length defined in the length section

            [ 0x02 ]  [ variable ]
            ----------------------
            | Length |  Data...  |
            ----------------------

In our case, the data is from one line of the Intel Hex formated .hex file

"""

from pb.bar import ShadyBar
from pb.spinner import Spinner
from serial import SerialException

import os
import argparse
import struct
import time
import math

from serial import Serial

# Initializing constants
RESP_OK = b'\x00'
RESP_ERR = b'\x01'
FRAME_SIZE = 16
PACKET_SIZE = 1024

error_counter = 0


# Send the metadata to the bootloader and wait for an "OK" message before proceeding
def send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=False):
    version, size, chunk_index, chunk_size  = struct.unpack('<hhhh', metadata)
    # Send the metadata to bootloader.
    ser.write(metadata)
    ser.write(nonce)
    ser.write(tag)
    ser.write(rsa_sign)

    resp = ser.read(1)
    if resp != RESP_OK:
        print("\n[X] Firmware update failed. Is the firmware file valid? (E_{})".format(repr(resp)))
        os._exit(1)

        
#Send each frame to the bootloader
def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame

    if debug:
        print(frame)
        
    resp = ser.read(1) # Wait for an OK from the bootloader

    if resp != RESP_OK: 
        print("\n[X] Firmware update failed. Is the firmware file valid? (E_{})".format(repr(resp)))
        os._exit(1)
        

def main(ser, infile, debug):
    print('\n\x1b[92mWelcome to the C.I.A. Firmware Update Tool!')
    print('(C) 2020 Completely Insecure Alice\x1b[0m\n')
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, 'rb') as fp:
        firmware_blob = fp.read()
    
    error_counter = 0
    
    # Handshake with bootloader, wait for bootloader to respond with a 'U'
    ser.write(b'U')

    spin = Spinner('Connecting to the bootloader... ')
    resp = ser.read(1)
    
    #Wait until 'U' is received
    while resp != b'U':
      spin.next()
      time.sleep(0.1)
    spin.finish()
    print('Success! Update will now begin.\n')
    
    # Iterate through all packets in the firmware blob, and split into 16 byte frames
    fw_size  = struct.unpack('<h', firmware_blob[2 : 4])[0]
    num_chunks = int(fw_size / PACKET_SIZE) 
    cur_loc = 0
    release = False;
    
    # Create a progress bar, and show it to the user
    bar = ShadyBar('\x1b[96mUpdating\x1b[0m', max=(math.ceil(fw_size/FRAME_SIZE)), suffix='%(percent)d%%') 
    
    # Iterate through all chunks until release message
    while(not release):
        metadata = firmware_blob[cur_loc:cur_loc + 8]
        nonce = firmware_blob[cur_loc + 8:cur_loc + 24]
        tag = firmware_blob[cur_loc + 24:cur_loc + 40]
        rsa_sign = firmware_blob[cur_loc + 40:cur_loc + 296]
        version, size, chunk_index, chunk_size  = struct.unpack('<hhhh', metadata)

        # Reached the release message (final chunk)
        if(chunk_index == -1):
            release = True;
        
        # Make sure each chunk size is a multiple of 16, and pad if it isn't
        actual_size = chunk_size
        if(chunk_size % 16 != 0):
            actual_size += (16 - (chunk_size % 16))
        
        # Prepare each chunk to be split into frames
        firmware = firmware_blob[cur_loc + 296: cur_loc + actual_size + 296]
        
        # Send metadata to bootloader with nonce, tag, and rsa signature
        send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=debug)
        
        # Iterate through each 16 byte frame in the chunk
        for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
            # Advance the progress bar
            bar.next() 
            
            # Get current frame
            data = firmware[frame_start: frame_start + FRAME_SIZE] 

            # Get length of data
            length = len(data)
            frame_fmt = '<{}s'.format(length)

            # Construct frame.
            frame = struct.pack(frame_fmt, data)

            # Send the frame to bootloader
            send_frame(ser, frame, debug=debug)
        
        # Shift current location forward to the next chunk
        cur_loc += (actual_size + 296)
    
    # Clean up progress bar and give user confirmation of success
    bar.finish()
    print("\n✔ Firmware update successfully installed.")
    return ser

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')

    parser.add_argument("--port", help="Serial port to send update over.",
                        required=True)
    parser.add_argument("--firmware", help="Path to firmware image to load.",
                        required=True)
    parser.add_argument("--debug", help="Enable debugging messages.",
                        action='store_true')
    args = parser.parse_args()
    try: # Check if specified serial port is open. 
      ser = Serial(args.port, baudrate=115200, timeout=2)
      main(ser=ser, infile=args.firmware, debug=args.debug)
    except SerialException:
      print('[!] Error: The serial port specified is not open.')
      os._exit(os.EX_OK) 