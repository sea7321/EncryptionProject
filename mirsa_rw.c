/// File: mirsa_rw.c
/// Description: Module to encode, encrypt & decode, decrypt
/// given input through standard input or by file.
///
/// @author Savannah Alfaro, sea2985
/// /// /// /// /// /// /// /// /// /// /// /// /// /// /// ///

// Includes
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include "mirsa_lib.h"

// Global Variables
static size_t VERBOSE = 0;
#define CHUNK_SIZE 4
#define PRINT_USAGE() {\
    fprintf(stderr, "\nusage:\nReader use: mirsa_rw [-vh] [-k keyname] -r cipherfile [plainfile]"); \
    fprintf(stderr, "\n\t\tIf plainfile is not provided, then reader output is to stdout.");\
    fprintf(stderr, "\nWriter use: mirsa_rw [-vh] [-k keyname] -w cipherfile [plainfile]");\
    fprintf(stderr, "\n\t\tIf plainfile is not provided, then writer input is from stdin.");\
    fprintf(stderr, "\nThe -v flag turns on verbose output.");\
}

/// Encodes and encrypts a given CHUNK_SIZE of a string and writes
/// it to the cipherFile.
/// @param stringInput (char *) input string to be encoded and encrypted
/// @param key (key_t *) input key given
/// @param cipherFile (FILE *) cipher file to write to
void encodeEncrypt(char * stringInput, key_t * key, FILE * cipherFile) {
    // read from stringInput
    if (VERBOSE) printf("Read: %s\n", stringInput);

    // encode
    if (VERBOSE) printf("------ ENCODING ------\n");
    uint64_t encoded = mr_encode(stringInput);
    if (VERBOSE) printf("Encoded: %lu\n", encoded);

    // encrypt
    if (VERBOSE) printf("------ ENCRYPTING ------\n");
    uint64_t encrypted = mr_encrypt(encoded, key);
    if (VERBOSE) printf("Encrypted: %lu\n", encrypted);

    // write to the cipher file
    if (VERBOSE) printf("------ WRITING TO CIPHER FILE ------\n");
    fwrite(&encrypted, sizeof(uint64_t), 1, cipherFile);
    if (VERBOSE) printf("Wrote: %lu\n", encrypted);
}

/// Decrypts, decodes, and returns the message of a given uint64_t.
/// @param intInput (uint64_t) input integer to be decrypted and decoded
/// @param key (key_t *) input key given
/// @return (char *) decrypted and decoded message
char * decryptDecode(uint64_t intInput, key_t * key) {
    // decrypt
    if (VERBOSE) printf("------ DECRYPTING ------\n");
    uint64_t decrypted = mr_decrypt(intInput, key);
    if (VERBOSE) printf("Decrypted: %lu\n", decrypted);

    // decode
    if (VERBOSE) printf("------ DECODING ------\n");
    char * decoded = mr_decode(decrypted);
    if (VERBOSE) printf("Decoded: %s\n", decoded);

    return decoded;
}

/// The main function which controls the argument parsing to read
/// or write to/from a given file to encode, encrypt or decode, decrypt
/// @param argc (int) number of command line arguments
/// @param argv (char *[]) command line arguments
/// @return (int) EXIT_SUCCESS if exited successfully
int main(int argc, char * argv[]) {
    // variables
    int opt;
    char * keyName;
    key_t * key;
    char * user;
    char stringInput[CHUNK_SIZE];
    uint64_t intInput;
    char * plainFileName;
    FILE * plainFile;
    FILE * cipherFile = NULL;
    _Bool writeFlag = 0;
    _Bool readFlag = 0;
    _Bool kFlag = 0;
    const char * cipherFileName;

    // argument parsing
    while((opt = getopt(argc, argv, "hk:w:r:v")) != -1) {
        switch (opt) {
            case 'h':
                PRINT_USAGE();
                exit(EXIT_SUCCESS);
            case 'k':
                kFlag = 1;
                keyName = optarg;
                break;
            case 'w':
                writeFlag = 1;
                cipherFileName = optarg;
                break;
            case 'r':
                readFlag = 1;
                cipherFileName = optarg;
                break;
            case 'v':
                VERBOSE = 1;
                mr_verbose(1);
                break;
            default:
                PRINT_USAGE();
                exit(EXIT_FAILURE);
        }
    }

    // get public/private key information
    char * fileName;
    if (kFlag) {
        if (writeFlag) {
            fileName = malloc(strlen(keyName) + 4);
            for (unsigned int i = 0; i < strlen(keyName); i++) {
                fileName[i] = keyName[i];
            }
            fileName[strlen(keyName)] = '.';
            fileName[strlen(keyName) + 1] = 'p';
            fileName[strlen(keyName) + 2] = 'u';
            fileName[strlen(keyName) + 3] = 'b';
            key = mr_read_keyfile(fileName);
        } else {
            fileName = malloc(strlen(keyName) + 4);
            for (unsigned int i = 0; i < strlen(keyName); i++) {
                fileName[i] = keyName[i];
            }
            fileName[strlen(keyName)] = '.';
            fileName[strlen(keyName) + 1] = 'p';
            fileName[strlen(keyName) + 2] = 'v';
            fileName[strlen(keyName) + 3] = 't';
            key = mr_read_keyfile(fileName);
        }
    } else {
        user = getlogin();
        if (writeFlag) {
            fileName = malloc(strlen(user) + 4);
            for (unsigned int i = 0; i < strlen(user); i++) {
                fileName[i] = user[i];
            }
            fileName[strlen(user)] = '.';
            fileName[strlen(user) + 1] = 'p';
            fileName[strlen(user) + 2] = 'u';
            fileName[strlen(user) + 3] = 'b';
            key = mr_read_keyfile(fileName);
        } else {
            fileName = malloc(strlen(user) + 4);
            for (unsigned int i = 0; i < strlen(user); i++) {
                fileName[i] = user[i];
            }
            fileName[strlen(user)] = '.';
            fileName[strlen(user) + 1] = 'p';
            fileName[strlen(user) + 2] = 'v';
            fileName[strlen(user) + 3] = 't';
            key = mr_read_keyfile(fileName);
        }
    }

    // print file name
    if (VERBOSE) printf("File Name: %s\n", fileName);

    if (writeFlag) {
        // open the cipher file
        cipherFile = fopen(cipherFileName, "w");

        // check to see if the file opened successfully
        if (cipherFile == NULL) {
            printf("ERROR\n");
            perror(cipherFileName);
            exit(EXIT_FAILURE);
        }

        // plain file given
        if (optind != argc) {
            // open the plain file
            plainFileName = argv[optind];
            plainFile = fopen(plainFileName, "r");

            // check to see if the file opened successfully
            if (plainFile == NULL) {
                printf("ERROR\n");
            }

            // read from the plain file
            if (VERBOSE) printf("------ READING PLAIN FILE ------\n");
            while(fgets(stringInput, CHUNK_SIZE, plainFile) != NULL) {
                encodeEncrypt(stringInput, key, cipherFile);
            }

            // close the plain file
            fclose(plainFile);
        } else {
            // read from standard input
            if (VERBOSE) printf("------ READING STANDARD INPUT ------\n");
            while(fgets(stringInput, CHUNK_SIZE, stdin)) {
                encodeEncrypt(stringInput, key, cipherFile);
            }
        }

        // close the cipher file
        fclose(cipherFile);
    } else if (readFlag) {
        // variables
        _Bool plainFlag = 0;

        // open the cipher file
        cipherFile = fopen(cipherFileName, "r");

        // check to see if the file opened successfully
        if (cipherFile == NULL) {
            printf("ERROR");
            perror(fileName);
            exit(EXIT_FAILURE);
        }

        // plain file given
        if (optind != argc) {
            // set plainFlag to true
            plainFlag = 1;

            // open the plain file
            plainFileName = argv[optind];
            plainFile = fopen(plainFileName, "r");

            // check to see if the file opened successfully
            if (plainFile == NULL) {
                printf("ERROR");
            }
        }

        // read cipher file
        if (VERBOSE) printf("------ READING CIPHER FILE ------\n");
        while (fread(&intInput, sizeof(uint64_t), 1, cipherFile) > 0) {
            if (VERBOSE) printf("Read: %lu\n", intInput);

            // decode intInput
            char * decoded = decryptDecode(intInput, key);

            if (plainFlag) {
                // write to the plain file
                if (VERBOSE) printf("------ WRITING TO PLAIN FILE ------\n");
                fputs(decoded, plainFile);
            } else {
                // write to standard output
                if (VERBOSE) printf("------ WRITING TO STANDARD OUTPUT ------\n");
                fprintf(stdout, "%s", decoded);
            }

            // wrote decoded string
            if (VERBOSE) printf("Wrote: %s\n", decoded);
        }

        // close the plain file
        if (plainFlag) fclose(plainFile);

        // close the cipher file
        fclose(cipherFile);
    } else {
        return -1;
    }
}
