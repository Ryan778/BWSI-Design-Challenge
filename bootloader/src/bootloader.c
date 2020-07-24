char aes_key[16] = AES_KEY;

// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
#include "inc/hw_types.h"  // Boolean type
#include "inc/hw_ints.h"   // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Application Imports
#include "uart.h"

#include "bearssl.h"

#include <string.h>
#include <math.h>

void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char*, unsigned int);

// Firmware Constants
#define METADATA_BASE 0x0000FC00  // base address of version and firmware size in Flash
#define FW_BASE       0x00010000  // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE  1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK     ((unsigned char)0x00)
#define ERROR  ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT   ((unsigned char)'B')

#define KEY_LEN 16  // Length of AES key (16 = AES-128)
#define IV_LEN  16  // Length of IV (16 is secure)

// Firmware v2 is embedded in bootloader
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *) (METADATA_BASE);
uint16_t *fw_size_address    = (uint16_t *) (METADATA_BASE + 2);
uint8_t  *fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

/*
 * Cryptographic Wrapper for BWSI: Embedded Security and Hardware Hacking
 * Uses BearSSL
 *
 * Ted Clifford
 * (C) 2020
 * 
 * These functions wrap their respective BearSSL implementations in a simpler interface.
 * Feel free to modify these functions to suit your needs.
 */

/*
 * AES-128 CBC Encrypt 
 * Parameters:
 * key - encryption key
 * iv - initialization vector
 * data - buffer of data to encrypt, ciphertext replaces the unencrypted data in this buffer
 * len - length of data (in bytes) (must be multiple of 16)
 * 
 * Returns:
 * 1 if encryption is successful
 */
// int aes_encrypt(char* key, char* iv, char* data, int len) {    
//     br_block_cbcenc_class* ve = &br_aes_big_cbcenc_vtable;
//     br_aes_gen_cbcenc_keys v_ec;
//     const br_block_cbcenc_class **ec;
    
//     ec = &v_ec.vtable;
//     ve->init(ec, key, KEY_LEN);
//     ve->run(ec, iv, data, len); 
    
//     return 1;
// }

/*
 * AES-128 CBC Decrypt
 * Parameters:
 * key - decryption key
 * iv - initialization vector
 * data - buffer of data to decrypt, plaintext replaces the encrypted data in this buffer 
 * len - length of data (in bytes) (must be multiple of 16)
 * 
 * Returns:
 * 1 if decryption is successful
 */
// int aes_decrypt(char* key, char* iv, char* ct, int len) {
//     br_block_cbcdec_class* vd = &br_aes_big_cbcdec_vtable;
//     br_aes_gen_cbcdec_keys v_dc;
//     const br_block_cbcdec_class **dc;
    
//     dc = &v_dc.vtable;
//     vd->init(dc, key, KEY_LEN);
//     vd->run(dc, iv, ct, len);
    
//     return 1;
// }

/*
 * AES-128 GCM Encrypt and Digest
 * Parameters:
 * key - encryption key
 * iv - initialization vector
 * pt - buffer of data to encrypt, ciphertext replaces the plaintext data in this buffer 
 * pt_len - length of plaintext (in bytes) (must be multiple of 16)
 * aad - buffer of additional authenticated data to add to tag
 * aad_len - length of aad (in bytes)
 * tag - output buffer for tag
 * 
 * Returns:
 * 1 if encryption is successful
 */
// int gcm_encrypt_and_digest(char* key, char* iv, char* pt, int pt_len, char* aad, int aad_len, char* tag) {
//     br_aes_ct_ctr_keys bc;
//     br_gcm_context gc;
//     br_aes_ct_ctr_init(&bc, key, KEY_LEN);
//     br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);
    
//     br_gcm_reset(&gc, iv, IV_LEN);
//     br_gcm_aad_inject(&gc, aad, aad_len);
//     br_gcm_flip(&gc);
//     br_gcm_run(&gc, 1, pt, pt_len);
//     br_gcm_get_tag(&gc, tag);
    
//     return 1;
// }

/*
 * AES-128 GCM Decrypt and Verify
 * Parameters:
 * key - decryption key
 * iv - initialization vector
 * ct - buffer of data to decrypt, plaintext replaces the ciphertext data in this buffer 
 * ct_len - length of ciphertext (in bytes) (must be multiple of 16)
 * aad - buffer of additional authenticated data to add to tag
 * aad_len - length of aad (in bytes)
 * tag - input buffer for tag
 * 
 * Returns:
 * 1 if tag is verified
 * 0 if tag is not verified
 * 
 * Note: Data will still be decrypted in place even if tag is not verified, it is up to you if you use it.
 */
int gcm_decrypt_and_verify(char* key, char* iv, char* ct, int ct_len, char* aad, int aad_len, char* tag) {
    br_aes_ct_ctr_keys bc;
    br_gcm_context gc;
    br_aes_ct_ctr_init(&bc, key, KEY_LEN);
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);
    
    br_gcm_reset(&gc, iv, IV_LEN);         
    br_gcm_aad_inject(&gc, aad, aad_len);    
    br_gcm_flip(&gc);                        
    br_gcm_run(&gc, 0, ct, ct_len);   
    if (br_gcm_check_tag(&gc, tag)) {
        return 1;
    }
    return 0; 
}

/*
 * SHA-256 Hash
 * Parameters:
 * data - buffer of data to hash
 * len - length of data (in bytes)
 * out - output buffer for hash (must be size in bytes of hash output)
 * 
 * Returns:
 * Length of hash
 */
// int sha_hash(unsigned char* data, unsigned int len, unsigned char* out) {
//     br_sha256_context csha;
    
//     br_sha256_init(&csha);
//     br_sha256_update(&csha, data, len);
//     br_sha256_out(&csha, out);
    
//     return 32;
// }

/*
 * SHA-256 HMAC
 * Parameters:
 * key - HMAC key
 * key_len - length of key (in bytes)
 * data - data buffer to verify
 * len - length of data (in bytes)
 * out - output buffer for HMAC (must be size in bytes of output)
 * 
 * Returns:
 * Length of HMAC
 */
// int sha_hmac(char* key, int key_len, char* data, int len, char* out) {
//     br_hmac_key_context kc;
//     br_hmac_context ctx;
//     br_hmac_key_init(&kc, &br_sha256_vtable, key, key_len);
//     br_hmac_init(&ctx, &kc, 0);
//     br_hmac_update(&ctx, data, len);
//     br_hmac_out(&ctx, out);
    
//     return 32;
// }

int get_data_size(float n, float m) {
  return ceil(n / m) * m;
}

int main(void) {
  // Initialize UART channels
  // 0: Reset
  // 1: Host Connection
  // 2: Debug
  uart_init(UART0);
  uart_init(UART1);
  uart_init(UART2);

  // Enable UART0 interrupt
  IntEnable(INT_UART0);
  IntMasterEnable();

  load_initial_firmware();

  uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
  uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
  uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

  int resp;
  while (true) {
    uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
    switch (instruction) {
      case UPDATE:
        uart_write_str(UART1, "U");
        load_firmware();
        break;
      case BOOT:
        uart_write_str(UART1, "B");
        boot_firmware();
        break;
    }
  }
  
  return 0;
}

/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void) {
  int  size = (int)&_binary_firmware_bin_size;
  int *data = (int *)&_binary_firmware_bin_start;
  
  uint16_t version  = 2;
  uint32_t metadata = (((uint16_t) size & 0xFFFF) << 16) | (version & 0xFFFF);
  program_flash(METADATA_BASE, (uint8_t*)(&metadata), 4);
  fw_release_message_address = (uint8_t *) "This is the initial release message.";
  
  int i = 0;
  for (; i < size / FLASH_PAGESIZE; i++) {
    program_flash(FW_BASE + (i * FLASH_PAGESIZE), ((unsigned char *) data) + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }
  program_flash(FW_BASE + (i * FLASH_PAGESIZE), ((unsigned char *) data) + (i * FLASH_PAGESIZE), size % FLASH_PAGESIZE);
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void) {
  int      read         =  0;
  int      index        =  0;
  int      pindex       = -1;
  int      frame_length =  16;
  uint32_t rcv          =  0;
  uint32_t data_index   =  0;
  uint32_t page_addr    =  FW_BASE;
  uint32_t temp_addr    =  0x00020000;
  uint32_t version      =  0;
  uint32_t size         =  0;
  uint32_t text_size    =  0;
  uint32_t fw_index     =  0;
  uint32_t metadata     =  0;
  unsigned char nonce[16];
  unsigned char tag[16];
  
  while (true) {
    // Get version.
    rcv      = uart_read(UART1, BLOCKING, &read);
    version  = (uint32_t)rcv;
    rcv      = uart_read(UART1, BLOCKING, &read);
    version |= (uint32_t)rcv << 8;
    uart_write_str(UART2, "Received Firmware Version: ");
    uart_write_hex(UART2, version);
    nl(UART2);
    
    // Get size.
    rcv   = uart_read(UART1, BLOCKING, &read);
    size  = (uint32_t)rcv;
    rcv   = uart_read(UART1, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;
    uart_write_str(UART2, "Received Firmware Size: ");
    uart_write_hex(UART2, size);
    nl(UART2);
    
    // Get index.
    rcv    = uart_read(UART1, BLOCKING, &read);
    index  = (uint32_t)rcv;
    rcv    = uart_read(UART1, BLOCKING, &read);
    index |= (uint32_t)rcv << 8;
    uart_write_str(UART2, "Received Index: ");
    uart_write_hex(UART2, index);
    nl(UART2);
    
    // Get text size.
    rcv        = uart_read(UART1, BLOCKING, &read);
    text_size  = (uint32_t)rcv;
    rcv        = uart_read(UART1, BLOCKING, &read);
    text_size |= (uint32_t)rcv << 8;
    uart_write_str(UART2, "Received Text Size: ");
    uart_write_hex(UART2, text_size);
    nl(UART2);
    
    // Get nonce.
    for (int i = 0; i < 16; i++) {
      nonce[i] = uart_read(UART1, BLOCKING, &read);
    }
    uart_write_str(UART2, "Received Nonce: ");
    uart_write_hex(UART2, nonce);
    nl(UART2);
    
    // Get tag.
    for (int i = 0; i < 16; i++) {
      tag[i] = uart_read(UART1, BLOCKING, &read);
    }
    uart_write_str(UART2, "Received Tag: ");
    uart_write_hex(UART2, tag);
    nl(UART2);
    
    // Metadata
    metadata = ((text_size & 0xFF) << 24) | ((index & 0xFF) << 16) | ((size & 0xFF) << 8) | (version & 0xFF);
    
    // Compare to old version and abort if older (note special case for version 0).
    uart_write_str(UART2, "Starting Version Check");
    nl(UART2);
    
    uint16_t old_version = *fw_version_address;
    if (version != 0 && version < old_version) {
      uart_write(UART1, ERROR); // Reject the metadata.
      SysCtlReset();            // Reset device
      return;
    } else if (version == 0) {
      // If debug firmware, don't change version
      version = old_version;
    }
    
    uart_write_str(UART2, "Version Check Done");
    nl(UART2);
    
    if (index == -1) {
      // Get Release Message
      for (int i = 0; i < get_data_size(text_size, 16) / frame_length; i++) {
        for (int j = 0; j < frame_length; j++) {
          data[data_index++] = uart_read(UART1, BLOCKING, &read);
        }
        uart_write(UART1, OK); // Acknowledge the frame.
      }
      
      // Verify Integrity and Decrypt
      if (gcm_decrypt_and_verify(aes_key, nonce, data, data_index, metadata, 8, tag) == 0) {
        uart_write(UART1, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
      }
      
      // Unpad
      if (text_size != 1024) {
        int pad = get_data_size(text_size, 16) - text_size;
        data_index -= pad;
        for (int i = data_index - 1; i < FLASH_PAGESIZE; i++) {
          data[i] = '\0';
        }
      }
      
      // Try to write flash and check for error
      if (program_flash(temp_addr + page_addr * FLASH_PAGESIZE, data, data_index)) {
        uart_write(UART1, ERROR); // Reject the firmware
        SysCtlReset();            // Reset device
        return;
      }
      
      memset(data, '\0', FLASH_PAGESIZE);
      
      // Verify firmware size
      if (fw_index != size) {
        uart_write(UART1, ERROR); // Reject the firmware
        SysCtlReset();            // Reset device
        return;
      }
      
      // Write new firmware size and version to Flash
      metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
      program_flash(METADATA_BASE, (uint8_t*)(&metadata), 4);
      
      // Read from temp_addr. Write to FW_BASE.
      int i = 0;
      for (; i < size / FLASH_PAGESIZE; i++) {
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), ((unsigned char *) temp_addr) + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
      }
      program_flash(FW_BASE + (i * FLASH_PAGESIZE), ((unsigned char *) temp_addr) + (i * FLASH_PAGESIZE), size % FLASH_PAGESIZE);
      
      // Write release message to Flash
      fw_release_message_address = (uint8_t *) (FW_BASE + size);
      program_flash(fw_release_message_address, ((unsigned char *) temp_addr) + ((i + 1) * FLASH_PAGESIZE), FLASH_PAGESIZE);
      
      // Clear temp_addr
      for (i = 0; i < (size / FLASH_PAGESIZE) + 2; i++) {
        FlashErase(temp_addr + (i * FLASH_PAGESIZE));
      }
      
      return;
    } else if (index == pindex + 1) {
      for (int i = 0; i < get_data_size(text_size, 16) / frame_length; i++) {
        for (int j = 0; j < frame_length; j++) {
          data[data_index++] = uart_read(UART1, BLOCKING, &read);
        }
        uart_write(UART1, OK); // Acknowledge the frame.
      }
      
      // Verify Integrity and Decrypt
      if (gcm_decrypt_and_verify(aes_key, nonce, data, data_index, metadata, 8, tag) == 0) {
        uart_write(UART1, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
      }
      
      // Unpad
      if (text_size != 1024) {
        int pad = get_data_size(text_size, 16) - text_size;
        data_index -= pad;
        for (int i = data_index - 1; i < FLASH_PAGESIZE; i++) {
          data[i] = '\0';
        }
      }
      
      // Try to write flash and check for error
      if (program_flash(temp_addr + page_addr * FLASH_PAGESIZE, data, data_index)) {
        uart_write(UART1, ERROR); // Reject the firmware
        SysCtlReset();            // Reset device
        return;
      }
      
      // Write debugging messages to UART2.
      uart_write_str(UART2, "Page successfully programmed\nAddress: ");
      uart_write_hex(UART2, temp_addr);
      uart_write_str(UART2, "\nBytes: ");
      uart_write_hex(UART2, data_index);
      nl(UART2);

      fw_index += data_index;
      pindex    = index;
      
      // Update to next page
      page_addr += 1;
      data_index = 0;
      memset(data, '\0', FLASH_PAGESIZE);
    } else {
      uart_write(UART1, ERROR); // Reject the metadata.
      SysCtlReset();            // Reset device
      return;
    }
  }
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len) {
  unsigned int padded_data_len;
  
  // Erase next FLASH page
  FlashErase(page_addr);
  
  // Clear potentially unused bytes in last word
  if (data_len % FLASH_WRITESIZE) {
    // Get number unused
    int rem = data_len % FLASH_WRITESIZE;
    for (int i = 0; i < rem; i++) {
      data[data_len - 1 - i] = 0x00;
    }
    // Pad to 4-byte word
    padded_data_len = data_len + (FLASH_WRITESIZE - rem);
  } else {
    padded_data_len = data_len;
  }
  
  // Write full buffer of 4-byte words
  return FlashProgram((unsigned long *)data, page_addr, padded_data_len);
}

void boot_firmware(void) {
  uart_write_str(UART2, (char *) fw_release_message_address);
  
  // Boot the firmware
  __asm(
    "LDR R0,=0x10001\n\t"
    "BX R0\n\t"
  );
}
