#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Don't redefine size_t - it's already in stddef.h included by stdio.h

// Undefine any existing type definitions to avoid conflicts
#ifdef u8
#undef u8
#endif
#ifdef u32
#undef u32
#endif
#ifdef u64
#undef u64
#endif
#ifdef usize
#undef usize
#endif

#include "SHA-256.h"

// Undefine and redefine for next header
#ifdef u8
#undef u8
#endif
#ifdef u32
#undef u32
#endif
#ifdef u64
#undef u64
#endif
#ifdef usize
#undef usize
#endif
#ifdef size_t
#undef size_t
#endif

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long long usize;

#include "AES-128-GCM.h"

// Undefine for HMAC-SHA256.h which uses typedef
#ifdef u8
#undef u8
#endif
#ifdef u32
#undef u32
#endif
#ifdef u64
#undef u64
#endif
#ifdef usize
#undef usize
#endif

#include "HMAC-SHA256.h"

// Undefine for ASN.1DER.h which uses #define
#ifdef u8
#undef u8
#endif
#ifdef u32
#undef u32
#endif
#ifdef u64
#undef u64
#endif
#ifdef usize
#undef usize
#endif
#ifdef size_t
#undef size_t
#endif

#include "ASN.1DER.h"

// Undefine for RSA-2048.h which uses #define
#ifdef u8
#undef u8
#endif
#ifdef u32
#undef u32
#endif
#ifdef u64
#undef u64
#endif
#ifdef usize
#undef usize
#endif
#ifdef size_t
#undef size_t
#endif

#include "RSA-2048.h"

// Undefine for X25519.h which uses typedef
#ifdef u8
#undef u8
#endif
#ifdef u32
#undef u32
#endif
#ifdef u64
#undef u64
#endif
#ifdef usize
#undef usize
#endif

#include "X25519.h"

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <algorithm_number> <string>\n", argv[0]);
        fprintf(stderr, "Algorithms:\n");
        fprintf(stderr, "  1 - AES-128-GCM\n");
        fprintf(stderr, "  2 - ASN.1 DER\n");
        fprintf(stderr, "  3 - HMAC-SHA256\n");
        fprintf(stderr, "  4 - RSA-2048\n");
        fprintf(stderr, "  5 - SHA-256\n");
        fprintf(stderr, "  6 - X25519\n");
        return 1;
    }

    int algo = atoi(argv[1]);
    const char *input = argv[2];
    size_t input_len = strlen(input);

    if (algo < 1 || algo > 6) {
        fprintf(stderr, "Error: algorithm number must be between 1 and 6\n");
        return 1;
    }

    switch (algo) {
        case 1: {
            // AES-128-GCM
            unsigned char key[16];
            unsigned char nonce[12];
            unsigned char ciphertext[1024];
            unsigned char tag[16];
            AES128GCMContext ctx;

            // Generate a simple key and nonce from input
            memset(key, 0, 16);
            memset(nonce, 0, 12);
            for (size_t i = 0; i < input_len && i < 16; i++) {
                key[i] = input[i];
            }
            for (size_t i = 0; i < input_len && i < 12; i++) {
                nonce[i] = input[i] ^ 0x55;
            }

            aes128gcm_init(&ctx, key);
            aes128gcm_encrypt(&ctx, nonce, NULL, 0, input, input_len, ciphertext, tag);

            printf("AES-128-GCM Encryption Result:\n");
            printf("Ciphertext: ");
            print_hex(ciphertext, input_len);
            printf("Tag: ");
            print_hex(tag, 16);
            break;
        }

        case 2: {
            // ASN.1 DER
            printf("ASN.1 DER Test:\n");
            printf("Input string: %s\n", input);
            printf("Input length: %zu\n", input_len);
            
            // Simple DER encoding example
            unsigned char der_data[256];
            size_t pos = 0;
            
            // Create a simple OCTET STRING
            if (input_len < 128) {
                der_data[pos++] = 0x04; // OCTET STRING tag
                der_data[pos++] = (unsigned char)input_len; // Length
                memcpy(der_data + pos, input, input_len);
                pos += input_len;
                
                printf("DER Encoded: ");
                print_hex(der_data, pos);
                
                // Parse it back
                DERReader reader;
                der_init(&reader, der_data, pos);
                unsigned char tag;
                const unsigned char *value;
                size_t value_len;
                if (der_read(&reader, &tag, &value, &value_len) == 0) {
                    printf("Decoded tag: 0x%02x\n", tag);
                    printf("Decoded value: ");
                    for (size_t i = 0; i < value_len; i++) {
                        printf("%c", value[i]);
                    }
                    printf("\n");
                } else {
                    printf("Failed to decode DER data\n");
                }
            } else {
                printf("Input too long for simple DER encoding example\n");
            }
            break;
        }

        case 3: {
            // HMAC-SHA256
            unsigned char hmac_result[32];
            unsigned char key[32] = "defaultkey";
            
            hmac_sha256(key, 10, input, input_len, hmac_result);
            
            printf("HMAC-SHA256(input, key=\"defaultkey\"): ");
            print_hex(hmac_result, 32);
            break;
        }

        case 4: {
            // RSA-2048 - Just hash and show
            unsigned char hash[32];
            SHA256Context sha_ctx;
            
            sha256_init(&sha_ctx);
            sha256_update(&sha_ctx, input, input_len);
            sha256_final(&sha_ctx, hash);
            
            printf("RSA-2048 Test (SHA-256 hash of input):\n");
            printf("Hash: ");
            print_hex(hash, 32);
            printf("This hash would be used for RSA-2048 signing/verification\n");
            break;
        }

        case 5: {
            // SHA-256
            unsigned char hash[32];
            SHA256Context sha_ctx;
            
            sha256_init(&sha_ctx);
            sha256_update(&sha_ctx, input, input_len);
            sha256_final(&sha_ctx, hash);
            
            printf("SHA-256: ");
            print_hex(hash, 32);
            break;
        }

        case 6: {
            // X25519
            unsigned char public_key[32];
            unsigned char private_key[32];
            
            // Generate a deterministic private key from input
            memset(private_key, 0, 32);
            for (size_t i = 0; i < input_len && i < 32; i++) {
                private_key[i] = input[i];
            }
            
            x25519_base(public_key, private_key);
            
            printf("X25519 Key Exchange:\n");
            printf("Private key (derived from input): ");
            print_hex(private_key, 32);
            printf("Public key: ");
            print_hex(public_key, 32);
            break;
        }
    }

    return 0;
}