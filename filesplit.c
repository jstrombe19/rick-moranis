/*
 * filesplit.c
 *
 * Splits a file into smaller encrypted chunks and writes its SHA256 hash to a .sha256 file.
 * Each chunk is encrypted using AES-256-CBC.
 * The encryption key is read from a key file. If the key file does not exist, a new key is generated and stored.
 * Each encrypted chunk file is named: <filename>.partNNN, and begins with a 16-byte IV.
 *
 * Compile with:
 *   gcc -o filesplit filesplit.c -lcrypto
 *
 * Usage:
 *   ./filesplit <file> <chunk_size> <key_file>
 *
 * Example:
 *   ./filesplit mylargefile.bin 1048576 mykey.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 8192
#define KEY_SIZE 32    // 256 bits for AES-256
#define IV_SIZE 16     // 16 bytes for AES block size

/* Compute SHA256 hash of a file. */
int compute_sha256(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        fclose(f);
        return -1;
    }
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, f)) > 0) {
        if (!SHA256_Update(&sha256, buffer, bytesRead)) {
            fclose(f);
            return -1;
        }
    }
    if (ferror(f)) {
        perror("fread");
        fclose(f);
        return -1;
    }
    if (!SHA256_Final(hash, &sha256)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* Convert a 32-byte hash into a hexadecimal string. */
void hash_to_string(unsigned char hash[SHA256_DIGEST_LENGTH], char *output) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/* Write the hash string into a file. */
int write_hash_to_file(const char *hash_filename, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *f = fopen(hash_filename, "w");
    if (!f) {
        perror("fopen hash file");
        return -1;
    }
    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_to_string(hash, hash_str);
    fprintf(f, "%s\n", hash_str);
    fclose(f);
    return 0;
}

/* Load the encryption key from the key file or generate one if not present.
 * The key is stored in the file as a 64-character hexadecimal string.
 */
int load_or_generate_key(const char *key_filename, unsigned char key[KEY_SIZE]) {
    FILE *kf = fopen(key_filename, "r");
    if (kf) {
        char hexkey[KEY_SIZE * 2 + 1];
        if (fgets(hexkey, sizeof(hexkey), kf) == NULL) {
            fclose(kf);
            fprintf(stderr, "Error reading key file.\n");
            return -1;
        }
        fclose(kf);
        // Convert hex string to binary key.
        for (int i = 0; i < KEY_SIZE; i++) {
            unsigned int byte;
            if (sscanf(&hexkey[i*2], "%2x", &byte) != 1) {
                fprintf(stderr, "Invalid key format in key file.\n");
                return -1;
            }
            key[i] = (unsigned char) byte;
        }
        printf("Encryption key loaded from %s\n", key_filename);
    } else {
        // Generate a new random key.
        if (RAND_bytes(key, KEY_SIZE) != 1) {
            fprintf(stderr, "Error generating random key.\n");
            return -1;
        }
        kf = fopen(key_filename, "w");
        if (!kf) {
            perror("fopen key file for writing");
            return -1;
        }
        for (int i = 0; i < KEY_SIZE; i++) {
            fprintf(kf, "%02x", key[i]);
        }
        fprintf(kf, "\n");
        fclose(kf);
        printf("New encryption key generated and saved to %s\n", key_filename);
    }
    return 0;
}

/* Split and encrypt the file into chunks. */
int split_file(const char *filename, size_t chunk_size, const unsigned char key[KEY_SIZE]) {
    /* Compute SHA256 of the original file */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (compute_sha256(filename, hash) != 0) {
        fprintf(stderr, "Failed to compute SHA256 hash of %s\n", filename);
        return 1;
    }
    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_to_string(hash, hash_str);
    printf("SHA256 (%s) = %s\n", filename, hash_str);

    /* Write the hash to a file named "<filename>.sha256" */
    char hash_filename[1024];
    snprintf(hash_filename, sizeof(hash_filename), "%s.sha256", filename);
    if (write_hash_to_file(hash_filename, hash) != 0) {
        fprintf(stderr, "Failed to write hash to %s\n", hash_filename);
        return 1;
    }
    printf("Hash written to %s\n", hash_filename);

    /* Open the original file for reading */
    FILE *in = fopen(filename, "rb");
    if (!in) {
        perror("fopen input file");
        return 1;
    }

    /* Determine file size */
    if (fseek(in, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(in);
        return 1;
    }
    long filesize = ftell(in);
    if (filesize < 0) {
        perror("ftell");
        fclose(in);
        return 1;
    }
    rewind(in);

    int chunk_index = 0;
    size_t bytes_remaining = filesize;
    while (bytes_remaining > 0) {
        /* Build chunk file name: <filename>.partNNN */
        char chunk_filename[1024];
        snprintf(chunk_filename, sizeof(chunk_filename), "%s.part%03d", filename, chunk_index);

        FILE *out = fopen(chunk_filename, "wb");
        if (!out) {
            perror("fopen chunk file");
            fclose(in);
            return 1;
        }

        /* Generate a random IV */
        unsigned char iv[IV_SIZE];
        if (RAND_bytes(iv, IV_SIZE) != 1) {
            fprintf(stderr, "Error generating IV.\n");
            fclose(out);
            fclose(in);
            return 1;
        }
        /* Write the IV at the beginning of the chunk file */
        if (fwrite(iv, 1, IV_SIZE, out) != IV_SIZE) {
            perror("fwrite IV");
            fclose(out);
            fclose(in);
            return 1;
        }

        /* Initialize the encryption context */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Error creating encryption context.\n");
            fclose(out);
            fclose(in);
            return 1;
        }
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            fprintf(stderr, "Error initializing encryption.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(out);
            fclose(in);
            return 1;
        }

        size_t bytes_to_encrypt = (bytes_remaining < chunk_size) ? bytes_remaining : chunk_size;
        size_t processed = 0;
        unsigned char inbuf[BUFFER_SIZE];
        unsigned char outbuf[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
        int outlen;

        /* Read up to bytes_to_encrypt from the input file and encrypt */
        while (processed < bytes_to_encrypt) {
            size_t to_read = (bytes_to_encrypt - processed) < BUFFER_SIZE ? (bytes_to_encrypt - processed) : BUFFER_SIZE;
            size_t n = fread(inbuf, 1, to_read, in);
            if (n == 0)
                break;
            processed += n;
            if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, n) != 1) {
                fprintf(stderr, "Encryption update error.\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(out);
                fclose(in);
                return 1;
            }
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
                perror("fwrite encrypted data");
                EVP_CIPHER_CTX_free(ctx);
                fclose(out);
                fclose(in);
                return 1;
            }
        }
        if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
            fprintf(stderr, "Encryption finalization error.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(out);
            fclose(in);
            return 1;
        }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            perror("fwrite final encrypted data");
            EVP_CIPHER_CTX_free(ctx);
            fclose(out);
            fclose(in);
            return 1;
        }
        EVP_CIPHER_CTX_free(ctx);
        fclose(out);

        printf("Created encrypted chunk: %s\n", chunk_filename);
        bytes_remaining -= processed;
        chunk_index++;
    }
    fclose(in);
    printf("File splitting and encryption complete. Total chunks: %d\n", chunk_index);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <file> <chunk_size> <key_file>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    size_t chunk_size = (size_t)atol(argv[2]);
    if (chunk_size == 0) {
        fprintf(stderr, "Invalid chunk size.\n");
        return 1;
    }
    const char *key_filename = argv[3];
    unsigned char key[KEY_SIZE];
    if (load_or_generate_key(key_filename, key) != 0) {
        fprintf(stderr, "Failed to load or generate encryption key.\n");
        return 1;
    }
    return split_file(filename, chunk_size, key);
}
