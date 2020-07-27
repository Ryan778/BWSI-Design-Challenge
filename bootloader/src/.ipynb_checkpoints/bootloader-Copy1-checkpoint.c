
static const unsigned char aes_key[] = {
    0xEA, 0xB1, 0xB0, 0x87, 0x60, 0xE2, 0x69, 0xF5,
    0xC9, 0x3F, 0xCB, 0x4F, 0x9E, 0x7D, 0xD0, 0x56,
};
static const unsigned char rsa_public_key[] = {
	0xEA, 0xB1, 0xB0, 0x87, 0x60, 0xE2, 0x69, 0xF5,
	0xC9, 0x3F, 0xCB, 0x4F, 0x9E, 0x7D, 0xD0, 0x56,
	0x54, 0x8F, 0xF5, 0x59, 0x97, 0x04, 0x3F, 0x30,
	0xE1, 0xFB, 0x7B, 0xF5, 0xA0, 0xEB, 0xA7, 0x7B,
	0x29, 0x96, 0x7B, 0x32, 0x48, 0x48, 0xA4, 0x99,
	0x90, 0x92, 0x48, 0xFB, 0xDC, 0xEC, 0x8A, 0x3B,
	0xE0, 0x57, 0x6E, 0xED, 0x1C, 0x5B, 0x78, 0xCF,
	0x07, 0x41, 0x96, 0x4C, 0x2F, 0xA2, 0xD1, 0xC8,
	0xA0, 0x5F, 0xFC, 0x2A, 0x5B, 0x3F, 0xBC, 0xD7,
	0xE6, 0x91, 0xF1, 0x44, 0xD6, 0xD8, 0x41, 0x66,
	0x3E, 0x80, 0xEE, 0x98, 0x73, 0xD5, 0x32, 0x60,
	0x7F, 0xDF, 0xBF, 0xB2, 0x0B, 0xA5, 0xCA, 0x11,
	0x88, 0x1A, 0x0E, 0xA1, 0x61, 0x4C, 0x5A, 0x70,
	0xCE, 0x12, 0xC0, 0x61, 0xF5, 0x50, 0x0E, 0xF6,
	0xC1, 0xC2, 0x88, 0x8B, 0xE5, 0xCE, 0xAE, 0x90,
	0x65, 0x23, 0xA7, 0xAD, 0xCB, 0x04, 0x17, 0x00,
	0xA2, 0xDB, 0xB0, 0x21, 0x49, 0xDD, 0x3C, 0x2E,
	0x8C, 0x47, 0x27, 0xF2, 0x84, 0x51, 0x63, 0xEB,
	0xF8, 0xAF, 0x63, 0xA7, 0x89, 0xE1, 0xF0, 0x2F,
	0xF9, 0x9C, 0x0A, 0x8A, 0xBC, 0x57, 0x05, 0xB0,
	0xEF, 0xA0, 0xDA, 0x67, 0x70, 0xAF, 0x3F, 0xA4,
	0x92, 0xFC, 0x4A, 0xAC, 0xEF, 0x89, 0x41, 0x58,
	0x57, 0x63, 0x0F, 0x6A, 0x89, 0x68, 0x45, 0x4C,
	0x20, 0xF9, 0x7F, 0x50, 0x9D, 0x8C, 0x52, 0xC4,
	0xC1, 0x33, 0xCD, 0x42, 0x35, 0x12, 0xEC, 0x82,
	0xF9, 0xC1, 0xB7, 0x60, 0x7B, 0x52, 0x61, 0xD0,
	0xAE, 0xFD, 0x4B, 0x68, 0xB1, 0x55, 0x0E, 0xAB,
	0x99, 0x24, 0x52, 0x60, 0x8E, 0xDB, 0x90, 0x34,
	0x61, 0xE3, 0x95, 0x7C, 0x34, 0x64, 0x06, 0xCB,
	0x44, 0x17, 0x70, 0x78, 0xC1, 0x1B, 0x87, 0x8F,
	0xCF, 0xB0, 0x7D, 0x93, 0x59, 0x84, 0x49, 0xF5,
	0x55, 0xBB, 0x48, 0xCA, 0xD3, 0x76, 0x1E, 0x7F
};
static const unsigned char rsa_modulus[] = {
	0x01, 0x00, 0x01
};
// unsigned char char rsa_public_key[256] = RSA_PUBLIC;
// unsigned char char rsa_modulus[6] = RSA_N;
// char aes_key[16] = AES_KEY;

// // Hardware Imports
// // #include "inc/hw_memmap.h" // Peripheral Base Addresses
// #include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
// #include "inc/hw_types.h"  // Boolean type
// #include "inc/hw_ints.h"   // Interrupt numbers

// // Driver API Imports
// #include "driverlib/flash.h"     // FLASH API
// #include "driverlib/sysctl.h"    // System control API (clock/reset)
// #include "driverlib/interrupt.h" // Interrupt API

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

// Declare RSA Public Key Object

static const br_rsa_public_key RSA_PK = {
	(void *)rsa_modulus, sizeof rsa_modulus,
	(void *)rsa_public_key, sizeof rsa_public_key
};

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

int rsa_verify(char* cipher, char* signature){
    br_rsa_pkcs1_vrfy fvrfy;
    int cipher_size = strlen(cipher);
    char hash[256];
    char output_hash_buffer[256];
    sha_hash(cipher, cipher_size, hash);
    fvrfy(signature, sizeof signature, BR_HASH_OID_SHA256, sizeof output_hash_buffer, &RSA_PK, output_hash_buffer)
    if(strcmp(output_hash_buffer, hash) == 0){
//         Success!!!
        return 1;
    }
    else{
//         OOOOOOPPPPPPPPPSSSSSS?
        return 0;
    }
    // compare hash to the hash of the message
    
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
int sha_hash(unsigned char* data, unsigned int len, unsigned char* out) {
    br_sha256_context csha;
    
    br_sha256_init(&csha);
    br_sha256_update(&csha, data, len);
    br_sha256_out(&csha, out);
    
    return 32;
}



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
        uart_write(UART1, OK);
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
    uint16_t old_version = *fw_version_address;
    if (version != 0 && version < old_version) {
      uart_write(UART1, ERROR); // Reject the metadata.
      SysCtlReset();            // Reset device
      return;
    } else if (version == 0) {
      // If debug firmware, don't change version
      version = old_version;
    }
    
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
