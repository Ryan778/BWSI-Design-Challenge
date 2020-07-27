#!/usr/bin/env python
"""
Firmware Updater Tool

1. Initializes update mode by sending and receiving a 'U'. 
   Sends the metadata to the bootloader.

2. Takes each packet from the firmware blob, splits it into 16 byte frames, and 
   sends each frame to the bootloader, and waits for an "OK" message after each 
   frame.
    - The OK message is just a zero

A frame consists of two sections:
    - Two bytes for the length of the data section
    - A data section of length defined in the length section

            [ 0x02 ]  [ variable ]
            ----------------------
            | Length |  Data...  |
            ----------------------

In our case, the data is from one line of the Intel Hex formated .hex file

"""

import argparse
import struct
import time

from serial import Serial

#initializing constants
RESP_OK = b'\x00'
RESP_ERR = b'\x01'
FRAME_SIZE = 16
PACKET_SIZE = 1024

error_counter = 0


#Send the metadata to the bootloader and wait for an "OK" message before proceeding
def send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=False):
    version, size, chunk_index, chunk_size  = struct.unpack('<hhhh', metadata)
    print(f'Version: {version}\nSize: {size} bytes\n')

    if debug:
        print(metadata)
        
    # Send the metadata to bootloader.
    ser.write(metadata)
    ser.write(nonce)
    ser.write(tag)
    ser.write(rsa_sign)

    # Wait for an OK from the bootloader.
    print("Still waiting....")
    time.sleep(0.1)
    
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

        
#Send each frame to the bootloader
def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame

    if debug:
        print(frame)
        
    time.sleep(0.1)    
    resp = ser.read(1)  # Wait for an OK from the bootloader

    print(f'resp{resp}')

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))
        
    #If the bootloader receives a one byte, resend the frame and increment error counter
    if resp == RESP_ERR:
        error_counter += 1
        send_frame(ser, frame, debug=debug)
        

def main(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, 'rb') as fp:
        firmware_blob = fp.read()
    
    error_counter = 0
    
    #Handshake with bootloader, wait for bootloader to respond with a 'U'
    ser.write(b'U')
    time.sleep(0.1)
    print('Waiting for bootloader to enter update mode...')
    resp = ser.read(1)
    print(resp)
    
    #Wait until 'U' is received
    while resp != b'U':
        resp = ser.read(1)
        print(resp)
        print('Waiting...')
    print('Updating...')
    
    #Iterate through all packets in the firmware blob, and split into 16 byte frames
    fw_size  = struct.unpack('<h', firmware_blob[2 : 4])[0]
    num_chunks = int(fw_size / PACKET_SIZE) 
    cur_loc = 0
    release = False;
    
    #Iterate through all chunks until release message
    while(not release):
        metadata = firmware_blob[cur_loc:cur_loc + 8]
        nonce = firmware_blob[cur_loc + 8:cur_loc + 24]
        tag = firmware_blob[cur_loc + 24:cur_loc + 40]
        rsa_sign = firmware_blob[cur_loc + 40:cur_loc + 296]
        version, size, chunk_index, chunk_size  = struct.unpack('<hhhh', metadata)
        
        #Reached the release message
        if(chunk_index == -1):
            release = True;
        
        #Make sure each chunk size is a multiple of 16
        actual_size = chunk_size
        if(chunk_size % 16 != 0):
            actual_size += (16 - (chunk_size % 16))
        
        #Each chunk to be split into frames
        firmware = firmware_blob[cur_loc + 296: cur_loc + actual_size + 296]
        print(len(firmware))
        print(firmware)
        
        #Send metadata to bootloader with nonce, tag, and rsa signature
        send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=debug)
        
        print(range(0, len(firmware), FRAME_SIZE))
        
        #Iterate through each 16 byte frame in the chunk
        for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
            print(f'Frame{idx}')
            data = firmware[frame_start: frame_start + FRAME_SIZE] #frame

            # Get length of data.
            length = len(data)
            frame_fmt = '<{}s'.format(length)

            # Construct frame.
            frame = struct.pack(frame_fmt, data)

            #If there are more than ten errors in a row, then restart the update.
            if error_counter > 10:
                print("Terminating, restarting update...")
                return

            if debug:
                print("Writing frame {} ({} bytes)...".format(idx, len(frame)))
            
            #Send the frame to bootloader
            send_frame(ser, frame, debug=debug)
            
    print("Done writing firmware.")
    return ser


#     for i in range(0, f):
#         print(f"Currently in chunk {i}")
      
#         metadata = firmware_blob[i * PACKET_SIZE : i * PACKET_SIZE = 1024 + 8]
#         nonce = firmware_blob[i * PACKET_SIZE = 1024 + 8 : i * PACKET_SIZE = 1024 + 24]
#         tag = firmware_blob[i * PACKET_SIZE = 1024 + 24 : i * PACKET_SIZE = 1024 + 40]
#         rsa_sign = firmware_blob[i * PACKET_SIZE = 1024 + 40 : i * PACKET_SIZE = 1024 + 296]
        
#         send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=debug)
 
#         fw_size  = struct.unpack('<H', firmware_blob[i * chunk_size + 2 : i * chunk_size + 4])[0]
#         chunk_size = struct.unpack('<H', firmware_blob[i * chunk_size + 6 : i * chunk_size + 8])[0]
#         packet_index = struct.unpack('<H', firmware_blob[i * chunk_size + 4 : i * chunk_size + 6])[0]
        
#         fw_start = PACKET_SIZE * packet_index + 296
#         firmware = firmware_blob[fw_start : fw_start + chunk_size]
  
#         for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
#             data = firmware[frame_start: frame_start + FRAME_SIZE]

#             # Get length of data.
#             length = len(data)
#             frame_fmt = '<{}s'.format(length)

#             # Construct frame.
#             frame = struct.pack(frame_fmt, data)

#             #If there are more than ten errors in a row, then restart the update.
#             if error_counter > 10:
#                 print("Terminating, restarting update...")
#                 return

#             if debug:
#                 print("Writing frame {} ({} bytes)...".format(idx, len(frame)))

#             send_frame(ser, frame, debug=debug)

    

    # Send a zero length payload to tell the bootlader to finish writing its page.
#     ser.write(struct.pack('<H', 0x0000))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')

    parser.add_argument("--port", help="Serial port to send update over.",
                        required=True)
    parser.add_argument("--firmware", help="Path to firmware image to load.",
                        required=True)
    parser.add_argument("--debug", help="Enable debugging messages.",
                        action='store_true')
    args = parser.parse_args()

    print('Opening serial port...')
    ser = Serial(args.port, baudrate=115200, timeout=2)
    main(ser=ser, infile=args.firmware, debug=args.debug)
