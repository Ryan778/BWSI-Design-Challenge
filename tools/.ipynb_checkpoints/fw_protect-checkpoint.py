"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def protect_firmware(infile, outfile, version, message):
    #Define constants
    CHUNK_SIZE = 1024
    BLOCK_SIZE = 16

    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        
    print("Firmware Size")
    print(len(firmware))
        
    #Load in Keys
    
    with open('secret_build_output.txt', 'rb') as fp:
        secrets = fp.read()

    key = secrets[0:16]
    rsa_key = RSA.import_key(secrets[16:])
    
    print("KEYS")
    
#     print(key)
    print(rsa_key.size_in_bytes())

    # Create variable to hold message
    msg = message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    # metadata = struct.pack('<HH', version, len(firmware))

    #Split firmware into 1K chunks

    chunks_needed = int(len(firmware)/CHUNK_SIZE)

    chunks=list()

    for i in range(chunks_needed):
        print(i)
        chunks.append(firmware[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE])

    if(CHUNK_SIZE * (chunks_needed) - len(firmware) != 0):
        chunks.append(firmware[CHUNK_SIZE * (chunks_needed):])
        
    for chunk in chunks:
        print(len(chunk))

    #Encrypt each chunk

    #Initialize AES

#     key = get_random_bytes(16) #For Testing Purposes only

    #Encrypt each Chunk with AES

    final_output = b'' #Final output?


    for i, chunk in enumerate(chunks):

        #Set up AES Cipher
        aes_cipher = AES.new(key, AES.MODE_GCM)
        
        #Set up metadata
        metadata = struct.pack('<hhhh', version, len(firmware), i,  len(chunk))
#         aes_cipher.update(metadata)
        
        #padded text
        processed_plain = b''
        if(len(chunk) == CHUNK_SIZE):
            processed_plain = chunk
        else:
            processed_plain = pad(chunk, BLOCK_SIZE)

        #Get Cipher Text
        ciphertext, tag = aes_cipher.encrypt_and_digest(processed_plain)
        
        #Get RSA Signature
        h = SHA256.new(ciphertext)
        signature = pkcs1_15.new(rsa_key).sign(h)

        #THings for testing :D
    #     print(metadata)
    #     print(ciphertext)
#         print(len(ciphertext))
#         print(tag)
    #     print(len(tag))

        #Add result to final output
        final_output += (metadata + aes_cipher.nonce + tag + signature + ciphertext)
        print(len(final_output))

    # Add release message

    aes_cipher = AES.new(key, AES.MODE_GCM)
    #Set up metadata
    metadata = struct.pack('<hhhh', version, len(firmware), -1,  len(message) )
    aes_cipher.update(metadata)
    #Get Cipher Text
    ciphertext, tag = aes_cipher.encrypt_and_digest(pad(msg, BLOCK_SIZE))
    #Get RSA Signature
    h = SHA256.new(ciphertext)
    signature = pkcs1_15.new(rsa_key).sign(h)
    #Final output
    final_output += (metadata + aes_cipher.nonce + tag + signature + ciphertext)

    #More Testing
    print(final_output)

#     Write firmware blob to outfile
    with open(outfile, 'wb') as outfile:
        outfile.write(final_output)
        

def decrypt(nonce_var, metadata, cipher_text, tag_var, key):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_var)
        cipher.update(metadata)
#         cipher.verify(tag_var)
        plaintext = cipher.decrypt_and_verify(cipher_text, tag_var)
        print(plaintext)
    except ValueError:
        print("AIYA")
        
def verify_rsa(ciphertext, key, signature):
    try:
        h = SHA256.new(ciphertext)
        pkcs1_15.new(key).verify(h, signature)
        print("yay")
        return 1
    except ValueError:
        print("Fail. Wrong Value")
        return 0
        
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
    
    
