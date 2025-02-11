/*
 * filejoin.c
 *
 * Reassembles encrypted chunk files into a single output file.
 * It expects encrypted chunks to be named: <base_name>.partNNN (NNN = 0, 1, 2, ...).
 * Each chunk file begins with a 16-byte IV.
 * The encryption key is read from the provided key file.
 * After joining and decryption, the SHA256 hash of the output file is computed and compared to the hash
 * stored in the provided hash file.
 *
 * Compile with:
 *   gcc -o filejoin filejoin.c -lcrypto
 *
 * Usage:
 *   ./filejoin <base_name> <num_chunks> <output_file> <hash_file> <key_file>
 *
 * Example:
 *   ./filejoin mylargefile.bin 10 reassembled.bin mylargefile.bin.sha256 mykey.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 8192
#define KEY_SIZE 32    // 256-bit key for AES-256
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

/* Load the encryption key from the key file.
 * The key file should contain a 64-character hexadecimal string.
 */
int load_key(const char *key_filename, unsigned char key[KEY_SIZE]) {
    FILE *kf = fopen(key_filename, "r");
    if (!kf) {
        perror("fopen key file");
        return -1;
    }
    char hexkey[KEY_SIZE * 2 + 1];
    if (fgets(hexkey, sizeof(hexkey), kf) == NULL) {
        fclose(kf);
        fprintf(stderr, "Error reading key file.\n");
        return -1;
    }
    fclose(kf);
    for (int i = 0; i < KEY_SIZE; i++) {
        unsigned int byte;
        if (sscanf(&hexkey[i*2], "%2x", &byte) != 1) {
            fprintf(stderr, "Invalid key format in key file.\n");
            return -1;
        }
        key[i] = (unsigned char) byte;
    }
    printf("Encryption key loaded from %s\n", key_filename);
    return 0;
}

/* Reassemble and decrypt the file from the encrypted chunks. */
int join_files(const char *base_name, int num_chunks, const char *output_filename,
               const char *hash_filename, const unsigned char key[KEY_SIZE]) {
    FILE *out = fopen(output_filename, "wb");
    if (!out) {
        perror("fopen output file");
        return 1;
    }

    for (int i = 0; i < num_chunks; i++) {
        char chunk_filename[1024];
        snprintf(chunk_filename, sizeof(chunk_filename), "%s.part%03d", base_name, i);
        FILE *in = fopen(chunk_filename, "rb");
        if (!in) {
            perror("fopen chunk file");
            fclose(out);
            return 1;
        }

        /* Read the IV from the beginning of the chunk file */
        unsigned char iv[IV_SIZE];
        if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
            fprintf(stderr, "Error reading IV from %s\n", chunk_filename);
            fclose(in);
            fclose(out);
            return 1;
        }

        /* Initialize the decryption context */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Error creating decryption context.\n");
            fclose(in);
            fclose(out);
            return 1;
        }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            fprintf(stderr, "Error initializing decryption.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }

        unsigned char inbuf[BUFFER_SIZE];
        unsigned char outbuf[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
        int outlen;
        size_t n;
        while ((n = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
            if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, n) != 1) {
                fprintf(stderr, "Decryption update error.\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(in);
                fclose(out);
                return 1;
            }
            if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
                perror("fwrite decrypted data");
                EVP_CIPHER_CTX_free(ctx);
                fclose(in);
                fclose(out);
                return 1;
            }
        }
        if (ferror(in)) {
            perror("fread");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
            fprintf(stderr, "Decryption finalization error or bad padding in %s.\n", chunk_filename);
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            perror("fwrite final decrypted data");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        printf("Merged and decrypted chunk: %s\n", chunk_filename);
    }
    fclose(out);
    printf("File reassembly and decryption complete. Output file: %s\n", output_filename);

    /* Compute SHA256 of the reassembled file */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (compute_sha256(output_filename, hash) != 0) {
        fprintf(stderr, "Failed to compute SHA256 of reassembled file.\n");
        return 1;
    }
    char computed_hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_to_string(hash, computed_hash_str);
    printf("SHA256 (%s) = %s\n", output_filename, computed_hash_str);

    /* Read the original hash from the provided hash file */
    FILE *hash_file_ptr = fopen(hash_filename, "r");
    if (!hash_file_ptr) {
        perror("fopen hash file");
        return 1;
    }
    char original_hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    if (fgets(original_hash_str, sizeof(original_hash_str), hash_file_ptr) == NULL) {
        fprintf(stderr, "Failed to read original hash from %s\n", hash_filename);
        fclose(hash_file_ptr);
        return 1;
    }
    original_hash_str[strcspn(original_hash_str, "\r\n")] = 0;
    fclose(hash_file_ptr);

    if (strcmp(computed_hash_str, original_hash_str) == 0) {
        printf("SHA256 hash matches the original file.\n");
    } else {
        printf("SHA256 hash does NOT match the original file!\n");
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <base_name> <num_chunks> <output_file> <hash_file> <key_file>\n", argv[0]);
        return 1;
    }
    const char *base_name = argv[1];
    int num_chunks = atoi(argv[2]);
    if (num_chunks <= 0) {
        fprintf(stderr, "Invalid number of chunks.\n");
        return 1;
    }
    const char *output_filename = argv[3];
    const char *hash_filename = argv[4];
    const char *key_filename = argv[5];
    unsigned char key[KEY_SIZE];
    if (load_key(key_filename, key) != 0) {
        fprintf(stderr, "Failed to load encryption key.\n");
        return 1;
    }
    return join_files(base_name, num_chunks, output_filename, hash_filename, key);
}
