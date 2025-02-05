/*
 * filejoin.c
 *
 * Reassembles chunk files into a single output file.
 * It expects chunks to be named: <base_name>.partNNN (NNN = 0, 1, 2, ...).
 * After joining, it computes the SHA256 of the output file and compares it to the hash
 * read from the provided hash file.
 *
 * Compile with:
 *   gcc -o filejoin filejoin.c -lcrypto
 *
 * Usage:
 *   ./filejoin <base_name> <num_chunks> <output_file> <hash_file>
 *
 * Example:
 *   ./filejoin mylargefile.bin 10 reassembled.bin mylargefile.bin.sha256
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 8192

/* Compute the SHA256 hash of a file.
 * The result (32 bytes) is stored in the 'hash' array.
 */
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

/* Convert a 32-byte hash into a hexadecimal string.
 * The 'output' buffer must be at least (SHA256_DIGEST_LENGTH * 2 + 1) bytes.
 */
void hash_to_string(unsigned char hash[SHA256_DIGEST_LENGTH], char *output) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/* Reassemble the file from chunks.
 * It expects chunk files named: <base_name>.partNNN for NNN=0 .. num_chunks-1.
 * After reassembly, the SHA256 of the output file is computed and compared to the hash read from 'hash_filename'.
 */
int join_files(const char *base_name, int num_chunks, const char *output_filename, const char *hash_filename) {
    FILE *out = fopen(output_filename, "wb");
    if (!out) {
        perror("fopen output file");
        return 1;
    }

    unsigned char buffer[BUFFER_SIZE];
    for (int i = 0; i < num_chunks; i++) {
        char chunk_filename[1024];
        snprintf(chunk_filename, sizeof(chunk_filename), "%s.part%03d", base_name, i);
        FILE *in = fopen(chunk_filename, "rb");
        if (!in) {
            perror("fopen chunk file");
            fclose(out);
            return 1;
        }
        size_t n;
        while ((n = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
            if (fwrite(buffer, 1, n, out) != n) {
                perror("fwrite");
                fclose(in);
                fclose(out);
                return 1;
            }
        }
        if (ferror(in)) {
            perror("fread");
            fclose(in);
            fclose(out);
            return 1;
        }
        fclose(in);
        printf("Merged chunk: %s\n", chunk_filename);
    }
    fclose(out);
    printf("File reassembly complete. Output file: %s\n", output_filename);

    /* Compute SHA256 of the reassembled file */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (compute_sha256(output_filename, hash) != 0) {
        fprintf(stderr, "Failed to compute SHA256 of reassembled file.\n");
        return 1;
    }
    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_to_string(hash, hash_str);
    printf("SHA256 (%s) = %s\n", output_filename, hash_str);

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
    /* Remove any trailing newline characters */
    original_hash_str[strcspn(original_hash_str, "\r\n")] = 0;
    fclose(hash_file_ptr);

    if (strcmp(hash_str, original_hash_str) == 0) {
        printf("SHA256 hash matches the original file.\n");
    } else {
        printf("SHA256 hash does NOT match the original file!\n");
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <base_name> <num_chunks> <output_file> <hash_file>\n", argv[0]);
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
    return join_files(base_name, num_chunks, output_filename, hash_filename);
}

