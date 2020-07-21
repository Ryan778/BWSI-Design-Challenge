// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h" // Peripheral Bit Masks and Registers
#include "inc/hw_types.h" // Boolean type
#include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h" // FLASH API
#include "driverlib/sysctl.h" // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Application Imports
#include "uart.h"

// Define lengths
#define KEY_LEN 0x10
#define NONCE_LEN 0x10
int main(){

    return 0;
}

int aes_gcm(){
//     Init: key, nonce, metadata, metdata_len, tag, ciphertext, cipher_len
    
    
//     Set up AES
    br_aes_ct_ctr_keys bc;
    br_aes_ct_ctr_init(&bc, key, KEY_LEN);
    
//     Set up GCM
    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);
    br_gcm_reset(&gc, nonce, NONCE_LEN);
    
//     Ready metadata
    br_gcm_aad_inject(&gc, metadata, metadata_len);
    br_gcm_flip(&gc);
    
//     Check tag
    
    if(br_gcm_check_tag(&gc, tag)){
//         Success!
//         Decrypting...
        br_gcm_run(&gc, 0, ciphertext, cipher_len);
    }
    else{
//         Failure!
    }
    
    return 0;
    
}

int rsa_decrypt(){
    br_rsa_pkcs1_vrfy fvrfy;
    br_rsa_public_key RSA_PK; //rsa public key
    fvrfy(signature, sizeof signature, BR_HASH_OID_SHA256, sizeof output_hash_buffer, &RSA_PK, output_hash_buffer)
    // compare hash to the hash of the message
    if(output_hash_buffer == msg_hash){
        //yay!
    }
}

