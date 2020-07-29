"""
Firmware Bundle-and-Protect Tool

1. Splits firmware binary into packets in the format shown below:

[ 0x02 ]   [ 0x02 ]  [ 0x02 ]  [ 0x02 ]    [ 0x16 ] [ 0x16 ]   [ 0x256 ]    [ 0x1024 ]
----------------------------------------------------------------------------------------
| Version | FW Size | Index | Chunk Size |  Nonce  |  Tag  | RSA Signature | FW Binary |
----------------------------------------------------------------------------------------

2. Encrypts and signs each packet individually using AES GCM 

3. Adds release message at the end of firmware blob, with packet index -1

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


#Splits firmware binary into packets, and encrypts + signs each packet
def protect_firmware(infile, outfile, version, message):
    #Define constants
    CHUNK_SIZE = 1024
    BLOCK_SIZE = 16

    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    #Load in Keys
    with open('secret_build_output.txt', 'rb') as fp:
        secrets = fp.read()

    key = secrets[0:16]
    rsa_key = RSA.import_key(secrets[16:])

    # Create variable to hold message
    msg = message.encode() + b'\00'


    #Split firmware into 1K chunks, make list of all the chunks
    chunks_needed = int(len(firmware)/CHUNK_SIZE)

    chunks=list()

    for i in range(chunks_needed):
        chunks.append(firmware[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE])

    #Add the remaining chunk from the firmware (that is not 1K bytes)
    if(CHUNK_SIZE * (chunks_needed) - len(firmware) != 0):
        chunks.append(firmware[CHUNK_SIZE * (chunks_needed):])

    #Encrypt each Chunk with AES
    final_output = b'' 

    #Encrypt each chunk
    for i, chunk in enumerate(chunks):

        #Initialize AES Cipher (GCM)
        aes_cipher = AES.new(key, AES.MODE_GCM)
        
        #Set up metadata: version, size, chunk index, chunk size
        metadata = struct.pack('<hhhh', version, len(firmware), i,  len(chunk))
        aes_cipher.update(metadata)
        
        #Pad text if not 1K chunk
        processed_plain = b''
        if(len(chunk) == CHUNK_SIZE):
            processed_plain = chunk
        else:
            processed_plain = pad(chunk, BLOCK_SIZE)

        #Get Cipher Text and tag
        ciphertext, tag = aes_cipher.encrypt_and_digest(processed_plain)
        
        #Get RSA Signature
        h = SHA256.new(ciphertext + metadata)
        signature = pkcs1_15.new(rsa_key).sign(h)

        #Add result to final output
        final_output += (metadata + aes_cipher.nonce + tag + signature + ciphertext)

    # Add release message, with packet index -1
    aes_cipher = AES.new(key, AES.MODE_GCM)
    #Set up metadata
    metadata = struct.pack('<hhhh', version, len(firmware), -1,  len(msg))
    aes_cipher.update(metadata)
    #Get Cipher Text
    processed_plain = b''
    if(len(msg) % BLOCK_SIZE == 0):
        processed_plain = msg
    else:
        processed_plain = pad(msg, BLOCK_SIZE)
    # Log some information
    print('> Output size:', len(final_output), 'bytes')
    print('> Release message:', processed_plain)
    ciphertext, tag = aes_cipher.encrypt_and_digest(processed_plain)
    #Get RSA Signature
    h = SHA256.new(ciphertext)
    signature = pkcs1_15.new(rsa_key).sign(h)
    #Final output
    final_output += (metadata + aes_cipher.nonce + tag + signature + ciphertext)
    
#   Write firmware blob to outfile
    with open(outfile, 'wb') as outfile:
        outfile.write(final_output)
       
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Protect Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()
    
    print('\n\x1b[92mWelcome to the C.I.A. Firmware Protect Tool!')
    print('(C) 2020 Completely Insecure Alice\x1b[0m\n')
    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
    print(f'\x1b[96m\nDone! File saved to {args.outfile}. GLHF!\x1b[0m')
