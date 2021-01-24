/// File: mirsa_lib.c
/// Description: Module to represent the public functions
/// to create public and private keys.
///
/// @author Savannah Alfaro, sea2985
/// /// /// /// /// /// /// /// /// /// /// /// /// /// /// ///

// Includes
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include "mirsa_lib.h"

// Global Variables
static size_t VERBOSE = 0;
FILE * filePub;
FILE * filePvt;
uint64_t publicKey;
uint64_t privateKey;
int NUMBER_OF_PRIMES;
#define BUFLENGTH 127
#define PRINT_USAGE() {\
    fprintf(stderr, "\nusage:\nReader use: mirsa_rw [-vh] [-k keyname] -r cipherfile [plainfile]"); \
    fprintf(stderr, "\n\t\tIf plainfile is not provided, then reader output is to stdout.");\
    fprintf(stderr, "\nWriter use: mirsa_rw [-vh] [-k keyname] -w cipherfile [plainfile]");\
    fprintf(stderr, "\n\t\tIf plainfile is not provided, then writer input is from stdin.");\
    fprintf(stderr, "\nThe -v flag turns on verbose output.");\
}

/// Finds the inverse of of e & phi.
/// @param e (uint64_t) the public key
/// @param phi (uint64_t) determines private key values
/// @return (int64_t) returns 0 if unsuccessful, otherwise d (private key)
int64_t inverse(int64_t e, uint64_t phi) {
    int64_t t = 0;
    int64_t newt = 1;
    int64_t tempt = 0;

    uint64_t r = phi;
    uint64_t newr = e;
    uint64_t tempr = phi;
    uint64_t quotient;

    while (newr != 0) {
        quotient = r/newr;

        tempt = newt;
        newt = t - (quotient * newt);
        t = tempt;

        tempr = newr;
        newr = r - (quotient * newr);
        r = tempr;
    }

    if (r > 1) {
        return (int64_t) NULL;
    }
    if (t < 0) {
        t = t + phi;
    }
    return t;
}

/// The RSA Key Generation Algorithm, which generates
/// the public and private keys.
/// @param p (uint64_t) first prime number
/// @param q (uint64_t) second prime number
/// @return (_Bool) true if generated keys successfully
_Bool generateKeys(uint64_t p, uint64_t q) {
    // variables
    uint64_t phi = (p - 1) * (q - 1);

    // finding the multiplicative
    for (int e = 3; e <= 9; e++) {
        if (VERBOSE) printf("Finding inverse. e = %d\n", e);
        int64_t d = inverse(e, phi);
        if (VERBOSE) printf("I got back %ld\n", d);
        if ((void *) d != NULL) {
            if (VERBOSE) printf("Found inverse, pub = %d, pvt = %ld\n\n", e, d);
            publicKey = e;
            privateKey = d;
            return 1;
        }
        if (VERBOSE) printf("Didn't find inverse for that e, trying again...\n\n");
    }
    return 0;
}

/// mr_verbose( bool value ) sets a flag to print diagnostic information.
/// Verbose content prints to stdout.
bool mr_verbose(bool value) {
    if (value == 0) {
        // turn verbose off
        VERBOSE = 0;
        return 1;
    } else {
        // turn verbose on
        VERBOSE = 1;
        return 0;
    }
}

/// mr_make_keys makes public and private key values and key files.
/// Product of p and q defines the maximum length of an encryptable message.
/// make keys and create key files or fail if (p, q) cannot work.
bool mr_make_keys(uint64_t p, uint64_t q, const char *user) {
    // variables
    const uint64_t nonce = p * q;

    // check to see if given proper key name
    if (user == NULL) {
        fprintf(stderr, "error: missing key file name.\n");
    }

    // generate public and private key
    if (!generateKeys(p, q)) {
        return 0;
    }

    // create a public and private basename
    char *baseNamePub = (char*) calloc(1, strlen((char*)user) + 5);
    char *baseNamePvt = (char*) calloc(1, strlen((char*)user) + 5);

    // attach proper file formats (pub)
    for (unsigned int i = 0; i < strlen(user); i++) {
        baseNamePub[i] = user[i];
    }
    baseNamePub[strlen(user)] = '.';
    baseNamePub[strlen(user) + 1] = 'p';
    baseNamePub[strlen(user) + 2] = 'u';
    baseNamePub[strlen(user) + 3] = 'b';


    // attach proper file formats (pub)
    for (unsigned int i = 0; i < strlen(user); i++) {
        baseNamePvt[i] = user[i];
    }
    baseNamePvt[strlen(user)] = '.';
    baseNamePvt[strlen(user) + 1] = 'p';
    baseNamePvt[strlen(user) + 2] = 'v';
    baseNamePvt[strlen(user) + 3] = 't';

    // create file for public baseName
    filePub = fopen(baseNamePub, "wb");
    fwrite(&publicKey, sizeof(uint64_t), 1, filePub);
    fwrite(&nonce, sizeof(uint64_t), 1, filePub);
    fclose(filePub);

    // create file for private baseName
    filePvt = fopen(baseNamePvt, "wb");
    fwrite(&privateKey, sizeof(uint64_t), 1, filePvt);
    fwrite(&nonce, sizeof(uint64_t), 1, filePvt);
    fclose(filePvt);

    // verbose output
    if (VERBOSE) {
        printf("------ Writing to Files ------\n");
        printf("Public File: %s\n", baseNamePub);
        printf("Private File: %s\n", baseNamePvt);
        printf("Public Key: (%lu, %lu)\n", (unsigned long) publicKey, (unsigned long) nonce);
        printf("Private Key: (%lu, %lu)\n\n", (unsigned long) privateKey, (unsigned long) nonce);
    }
    free(baseNamePub);
    free(baseNamePvt);
    return 1;
}

/// mr_read_keyfile reads a keypair from the specified file.
/// The result is a key structure on the heap or NULL on failure.
key_t * mr_read_keyfile(const char *file_name) {
    // variables
    FILE *file;
    uint64_t x;
    uint64_t nonce;

    // malloc memory for a keypair
    key_t *key = (key_t *) malloc(sizeof(struct key_s));

    // open the file
    file = fopen(file_name, "rb");

    // check to see if the file opened successfully
    if (file == NULL) {
        if (errno == 2) {
            fprintf(stderr, "error: missing file argument");
            PRINT_USAGE();
        } else {
            fprintf(stderr, "error: mr_read_keyfile: '%s': %s\n", file_name, strerror(errno));
        }
        return NULL;
    }

    // read from the file
    fread(&x, sizeof(uint64_t), 1, file);
    fread(&nonce, sizeof(uint64_t), 1, file);

    // check to see if actually read from the file
    if (ferror(file)) {
        fprintf(stderr, "error: mr_read_keyfile: '%s': read error\n", file_name);
        clearerr(file);
    }

    // assign key and nonce to key
    key->key = x;
    key->nonce = nonce;

    // verbose output
    if (VERBOSE) {
        printf("e/d value: %lu\n", x);
        printf("nonce: %lu\n", nonce);
    }
    return key;
}

/// Finds all the successful exponents and puts those numbers into an array (powers)
/// @param value (uint64_t) e/d value given
/// @return
uint64_t modPowers(uint64_t multiple, uint64_t value, uint64_t nonce) {
    // variables
    int count = 0;
    int maxCount;
    uint64_t secondValue = value;

    // count the number of exponents that will be in powers
    while (value != 0) {
        uint64_t number = floor(log2(value));
        uint64_t save = pow(2, number);
        value = value - save;
        count++;
    }

    // set maxCount to count
    maxCount = count;

    // create powers
    uint64_t * powers = (uint64_t *) malloc(count * sizeof(uint64_t));
    uint64_t * multiples = (uint64_t *) malloc(count * sizeof(uint64_t));

    // save each exponent in powers
    while (secondValue != 0) {
        uint64_t number = floor(log2(secondValue));
        uint64_t save = pow(2, number);
        secondValue = secondValue - save;
        powers[count - 1] = save;
        count--;
    }

    // calculate first possible multiple
    uint64_t possibleMultiple = multiple % nonce;
    count = 0;

    // loop through all possible bit values
    for (unsigned int i = 1; i <= powers[maxCount - 1]; i = 2 * i) {
        // add the possible multiple if it matches one of the powers
        if (i == powers[count]) {
            // save the multiple and update count
            multiples[count] = possibleMultiple;
            count++;
        }

        // update multiple
        possibleMultiple = (possibleMultiple * possibleMultiple) % nonce;
    }

    // loop through each valid multiple and multiply
    uint64_t result = multiples[0];
    for (int i = 1; i < maxCount; i++) {
        result = (result * multiples[i]) % nonce;
    }

    // free memory
    free(powers);
    free(multiples);
    return result;
}

/// Encrypt the encoded message, p, using public key pair pubkey(e, n).
uint64_t mr_encrypt(uint64_t p, const key_t * pubkey) {
    // variables
    uint64_t result;

    // encrypt
    if (VERBOSE) printf("P Value: %lu\nKey: %lu\nNonce: %lu\n", p, pubkey->key, pubkey->nonce);
    result = modPowers(p, pubkey->key, pubkey->nonce);
    return result;
}

/// Decrypt the encrypted cipher, c, using the private key pair pvtkey(d, n).
uint64_t mr_decrypt(uint64_t c, const key_t * pvtkey) {
    // variables
    uint64_t result;

    // decrypt
    if (VERBOSE) printf("P Value: %lu\nKey: %lu\nNonce: %lu\n", c, pvtkey->key, pvtkey->nonce);
    result = modPowers(c, pvtkey->key, pvtkey->nonce);
    return result;
}

/// Converts a string to an unsigned long code.
uint64_t mr_encode(const char * st) {
    // variables
    unsigned int result[2 * strlen(st) + 1];
    char * output = (char *) malloc(2 * strlen(st) + 1);

    // loop through each character in string
    for (unsigned int i = 0; i < strlen(st); i++) {
        // convert each character to hex and concatenate
        if (VERBOSE) printf("Encoding -> Character: %c\n", st[i]);
        sprintf((char *) result, "%2x", st[i]);
        strcat(output, (char *) result);
    }
    // convert hex string to uint64_t
    if (VERBOSE) printf("Encoding -> Output: %s\n", output);
    return strtoul(output, NULL, 16);
}

/// Converts an unsigned code to string.
char * mr_decode(uint64_t code) {
    // variables
    unsigned int ch;
    char hexString[9];
    char * output = (char *) malloc(5 * sizeof(char));

    // convert uint64_t to a hex string
    unsigned hexLength = sprintf(hexString, "%lx", code);
    char * hexPointer = hexString;

    // loop through each value in output
    for (unsigned int i = 0; i < hexLength / 2; i++) {
        // convert hex string to int, then to char
        if (VERBOSE) printf("Decoding -> HexString: %s\n", hexPointer);
        sscanf(hexPointer, "%2x", &ch);
        output[i] = (char) ch;
        if (VERBOSE) printf("Decoding -> Character: %c\n", output[i]);
        hexPointer += 2;
    }
    return output;
}
