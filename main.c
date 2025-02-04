#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "MxTypedef.h"
// Constants
#define AES_KEY_SIZE 32  // AES 256 key size (32 bytes)
#define AES_IV_SIZE 12   // AES GCM default IV size (12 bytes)
#define AES_TAG_SIZE 16  // AES GCM tag size (16 bytes)
#define FAIL -1
#define NIL 0
#define PRABHAKAR 1



// typedef unsigned char UINT8PTR;

// Function to print the hexadecimal representation of a byte buffer
void printHex(UINT8PTR buffer, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

// AES-GCM encryption function
INT32 AesGcmEncrypt(UINT8PTR plainText, INT32 plainTextLen, UINT8PTR aad, INT32 aadLen, UINT8PTR key, UINT8PTR iv, UINT8PTR ciphertext, UINT8PTR tag) {
    EVP_CIPHER_CTX *ctx;
    INT32 len;
    INT32 cipherTextLen;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return NIL;
    }

    // Initialise the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return NIL;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Set IV length (default is 12 bytes (96 bits) for AES-GCM)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        return FAIL;
    }

    // Initialise key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return NIL;
    }

    // Provide any AAD data
    if(aadLen)
    {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aadLen))
        {
            return NIL;
        }
    }

    // Encrypt the plaintext and write to ciphertext buffer
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plainText, plainTextLen)) {
        return NIL;
    }
    cipherTextLen = len;

    // Finalise the encryption and get the remaining ciphertext
    if (1 != EVP_EncryptFinal_ex(ctx, (ciphertext + cipherTextLen), &len)) {
        return NIL;
    }
    cipherTextLen += len;

    // Get the authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag)) {
        return NIL;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return cipherTextLen;
}

// AES-GCM decryption function
INT32 AesGcmDecrypt(UINT8PTR ciphertext, INT32 cipherTextLen, UINT8PTR aad, INT32 aadLen, UINT8PTR key, UINT8PTR iv, UINT8PTR plainText, UINT8PTR tag) {
    EVP_CIPHER_CTX *ctx;
    INT32 len;
    INT32 plainTextLen;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return NIL;
    }

    // Initialise the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return NIL;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        return FAIL;
    }

    // Initialise key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return NIL;
    }

    // Provide any AAD data
    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aadLen)) {
        return NIL;
    }

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plainText, &len, ciphertext, cipherTextLen)) {
        return NIL;
    }
    plainTextLen = len;

    // Set the expected tag for authentication
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, tag)) {
        return NIL;
    }

    // Finalise decryption and check for tag verification
    if (1 != EVP_DecryptFinal_ex(ctx, plainText + plainTextLen, &len)) {
        return NIL;  // Decryption failed or tag mismatch
    }
    plainTextLen += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plainTextLen;
}

// Function to generate a random key and IV
int generateKeyAndIv(UINT8PTR key, UINT8PTR iv) {
    if (!RAND_bytes(key, AES_KEY_SIZE)) {
        return 0;
    }
    if (!RAND_bytes(iv, AES_IV_SIZE)) {
        return 0;
    }
    return 1;
}

int main() {
    // Input data (plain text to encrypt)
    const char *plainText = "This is a secret message!";
    int plainTextLen = strlen(plainText);

    // Additional Authenticated Data (AAD)
//     const char *aad = "Additional Authenticated Data";
//     int aadLen = strlen(aad);
    const char *aad ;
    int aadLen = 0;

    // Prepare buffers
    UINT8PTR key = (UINT8PTR)malloc(AES_KEY_SIZE);
    UINT8PTR iv = (UINT8PTR)malloc(AES_IV_SIZE);
    UINT8PTR tag = (UINT8PTR)malloc(AES_TAG_SIZE);
    UINT8PTR ciphertext = (UINT8PTR)malloc(plainTextLen + AES_TAG_SIZE);
    UINT8PTR decryptedText = (UINT8PTR)malloc(plainTextLen);

    if (!key || !iv || !tag || !ciphertext || !decryptedText) {
        printf("Memory allocation failed.\n");
        return 1;
    }

    // Generate random key and IV
    if (!generateKeyAndIv(key, iv)) {
        printf("Failed to generate key and IV.\n");
        return 1;
    }

    printf("Key: ");
    printHex(key, AES_KEY_SIZE);
    printf("IV: ");
    printHex(iv, AES_IV_SIZE);

    // Encrypt the plaintext
    int cipherTextLen = AesGcmEncrypt((UINT8PTR)plainText, plainTextLen, (UINT8PTR)aad, aadLen, key, iv, ciphertext, tag);
    if (cipherTextLen == NIL) {
        printf("Encryption failed.\n");
        return 1;
    }

    printf("Ciphertext: ");
    printHex(ciphertext, cipherTextLen);
    printf("Tag: ");
    printHex(tag, AES_TAG_SIZE);
//     return;

    // Decrypt the ciphertext
    int decryptedTextLen = AesGcmDecrypt(ciphertext, cipherTextLen, (UINT8PTR)aad, aadLen, key, iv, decryptedText, tag);
    if (decryptedTextLen == NIL) {
        printf("Decryption failed.\n");
        return 1;
    }

    // Null-terminate decrypted text and print
    decryptedText[decryptedTextLen] = '\0';
    printf("Decrypted text: %s\n", decryptedText);

    // Cleanup
    free(key);
    free(iv);
    free(tag);
    free(ciphertext);
    free(decryptedText);

    return 0;
}

