/*
 * filesplit.c
 *
 * Splits a file into smaller chunks and writes its SHA256 hash to a .sha256 file.
 * Each chunk is named: <filename>.partNNN (with NNN zero‐padded).
 *
 * Compile with:
 *   gcc -o filesplit filesplit.c -lcrypto
 *
 * Usage:
 *   ./filesplit <file> <chunk_size>
 *
 * Example:
 *   ./filesplit mylargefile.bin 1048576
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

/* Write the hex string version of the hash into the file 'hash_filename'. */
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

/* Split the file into chunks of size 'chunk_size'.
 * The original file’s SHA256 hash is computed and stored.
 */
int split_file(const char *filename, size_t chunk_size) {
    /* Compute SHA256 of the original file */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (compute_sha256(filename, hash) != 0) {
        fprintf(stderr, "Failed to compute SHA256 hash of %s\n", filename);
        return 1;
    }
    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_to_string(hash, hash_str);
    printf("SHA256 (%s) = %s\n", filename, hash_str);

    /* Write hash to a file named "<filename>.sha256" */
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
    unsigned char buffer[BUFFER_SIZE];
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

        size_t bytes_to_write = (bytes_remaining < chunk_size) ? bytes_remaining : chunk_size;
        size_t written_total = 0;
        while (written_total < bytes_to_write) {
            size_t to_read = (bytes_to_write - written_total) < BUFFER_SIZE ? (bytes_to_write - written_total) : BUFFER_SIZE;
            size_t n = fread(buffer, 1, to_read, in);
            if (n == 0)
                break;
            size_t written = fwrite(buffer, 1, n, out);
            if (written != n) {
                perror("fwrite");
                fclose(out);
                fclose(in);
                return 1;
            }
            written_total += n;
        }
        fclose(out);
        printf("Created chunk: %s\n", chunk_filename);
        bytes_remaining -= written_total;
        chunk_index++;
    }
    fclose(in);
    printf("File splitting complete. Total chunks: %d\n", chunk_index);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <chunk_size>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    size_t chunk_size = (size_t)atol(argv[2]);
    if (chunk_size == 0) {
        fprintf(stderr, "Invalid chunk size.\n");
        return 1;
    }
    return split_file(filename, chunk_size);
}

