#!/usr/bin/env python
"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time

from serial import Serial

RESP_OK = b'\x00'
RESP_ERR = b'\x01'
FRAME_SIZE = 16
PACKET_SIZE = 1024

error_counter = 0

def send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=False):
    version, size, chunk_index, chunk_size  = struct.unpack('<hhhh', metadata)
    print(f'Version: {version}\nSize: {size} bytes\nChunk: {chunk_size} bytes\nIndex: {chunk_index}\n')

    # Send the metadata to bootloader.
    if debug:
        print(metadata)

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

def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print(frame)

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
    
    ser.write(b'U')
    
    
    print('Waiting for bootloader to enter update mode...')
    resp = ser.read(1)
    print(resp)
    while resp != b'U':
        resp = ser.read(1)
        print(resp)
        print('Waiting...')
    print('Updating...')
    
    fw_size  = struct.unpack('<h', firmware_blob[2 : 4])[0]
    num_chunks = int(fw_size / PACKET_SIZE) # maybe
    cur_loc = 0
    release = False;
    
    while(not release):
        print(cur_loc)
        metadata = firmware_blob[cur_loc:cur_loc + 8]
        nonce = firmware_blob[cur_loc + 8:cur_loc + 24]
        tag = firmware_blob[cur_loc + 24:cur_loc + 40]
        rsa_sign = firmware_blob[cur_loc + 40:cur_loc + 296]
        
        version, size, chunk_index, chunk_size  = struct.unpack('<hhhh', metadata)
        
        print(f'Chunk Index: {chunk_index}')
        
        if(chunk_index == -1):
            release = True;
        
        actual_size = chunk_size
        
        if(chunk_size % 16 != 0):
            actual_size += (16 - (chunk_size % 16))
        
        firmware = firmware_blob[cur_loc + 296: cur_loc + actual_size + 296]
        print(len(firmware))
        print(firmware)
        
        send_metadata(ser, metadata, nonce, tag, rsa_sign, debug=debug)
        
        print(range(0, len(firmware), FRAME_SIZE))
        for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
            print(f'Frame{idx}')
            data = firmware[frame_start: frame_start + FRAME_SIZE]

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

            send_frame(ser, frame, debug=debug)
            
        cur_loc += (actual_size + 296)
            
        
    
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

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing its page.
#     ser.write(struct.pack('<H', 0x0000))

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

    print('Opening serial port...')
    ser = Serial(args.port, baudrate=115200, timeout=2)
    main(ser=ser, infile=args.firmware, debug=args.debug)
