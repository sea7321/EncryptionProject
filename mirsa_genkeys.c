/// File: mirsa_genkeys.c
/// Description: Main module to randomly generate private and
/// public keys.
///
/// @author Savannah Alfaro, sea2985
/// /// /// /// /// /// /// /// /// /// /// /// /// /// /// ///

// Includes
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "mirsa_lib.h"

// Global Variables
static size_t VERBOSE = 0;
extern int NUMBER_OF_PRIMES;
static uint64_t * primes;
#define BUFLENGTH 1024
#define USAGE_MSG "usage: mirsa_genkeys [-hv] [-k keyname] [-s seed]\n"

/// Prints a message if VERBOSE is true (turned on).
/// @param message (char *) message to print
void verboseMessage(char * message) {
    if (VERBOSE) printf("%s\n", message);
}

/// Generates random primes and creates an array to
/// store the values of the primes.
/// @param fileName (char *) name of the file (Primes.txt)
/// @return (_Bool) true if generated primes (array) successfully
_Bool generateRandomPrimes(char *fileName) {
    // variables
    FILE *file;
    char *line, buf[BUFLENGTH];
    int count = 0;
    char * token;

    // open the file
    file = fopen(fileName, "r");

    // check to see if the file opened successfully
    if (file == NULL) {
        return NULL;
    }

    // read the first line of the file & malloc memory for primes
    line = fgets(buf, BUFLENGTH, file);
    NUMBER_OF_PRIMES = strtol(line, NULL, 10);
    primes = (uint64_t *) calloc(sizeof(uint64_t), NUMBER_OF_PRIMES);

    // read the remaining lines of the file
    while ((line = fgets(buf, BUFLENGTH, file)) != NULL) {
        // get first token on the line (if there is one)
        token = strtok(line, "\t");
        // add token to primes
        primes[count] = strtol(token, NULL, 10);
        count++;

        while ((token = strtok(NULL, "\t")) != NULL) {
            // add token to primes
            primes[count] = strtol(token, NULL, 10);
            // update count
            count++;
        }
    }

    // check to see if primes file has valid count
    if ((primes[NUMBER_OF_PRIMES - 1] == 0) || fgets(buf, BUFLENGTH, file) != NULL) {
        // too little number of primes given or too many primes given
        fprintf(stderr, "error: primes file has invalid count.\n");
    }

    // print out primes
    if (VERBOSE) {
        for (int i = 0; i < NUMBER_OF_PRIMES; i++) {
            printf("prime%d: %lu ", i, primes[i]);
        }
        printf("\n\n");
    }

    // return true if successful
    fclose(file);
    return 1;
}

/// Main function to process command line flags, read key files,
/// randomly select primes, and try to make public/private keys.
/// @param argc (int) number of command line arguments
/// @param argv (char *) command line arguments
/// @return (int) EXIT_SUCCESS if exited successfully
int main(int argc, char * argv[]) {
    // variables
    int opt;
    char * user = NULL;
    _Bool seedFlag = 0;
    int seed;
    int firstPrime;
    int secondPrime;
    int overflowCount = 0;
    int unsuccessfulKeyCount = 0;
    int foundInv = 0;

    // argument parsing
    while((opt = getopt(argc, argv, "hk:s:v")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, USAGE_MSG);
                exit(EXIT_SUCCESS);
            case 'k':
                user = optarg;
                if (optarg[0] == '-') {
                    fprintf(stderr, "error: -k requires argument, given: '%s'.", optarg);
                    fprintf(stderr, USAGE_MSG);
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                if (strtol(optarg, NULL, 10) == 0 && optarg[0] != 0) {
                    fprintf(stderr, "error: invalid seed value '%s'.", optarg);
                    fprintf(stderr, USAGE_MSG);
                    exit(EXIT_FAILURE);
                }
                seedFlag = 1;
                seed = strtol(optarg, NULL, 10);
                break;
            case 'v':
                VERBOSE = 1;
                mr_verbose(1);
                break;
            default:
                fprintf(stderr, USAGE_MSG);
                exit(EXIT_FAILURE);
        }
    }

    if (optind != argc) {
        fprintf(stderr, "error: extra argument: '%s'.", argv[optind]);
        fprintf(stderr, USAGE_MSG);
        exit(EXIT_FAILURE);
    }

    if (user == NULL) {
        user = getlogin();
    }

    // generate random prime numbers
    verboseMessage("------ Reading Primes ------");
    if (!generateRandomPrimes("Primes.txt")) {
        fprintf(stderr, "error: missing primes file.\n");
    }
    if (seedFlag) {
        srand(seed);
    } else {
        srand(time(0));
    }
    verboseMessage("------ Generating Random Primes -----");
    firstPrime = rand() % NUMBER_OF_PRIMES;
    secondPrime = rand() % NUMBER_OF_PRIMES;
    uint64_t p = primes[firstPrime];
    uint64_t q = primes[secondPrime];
    uint64_t nonce = p * q;

    if (VERBOSE) {
        printf("Seed: %d\n", seed);
        printf("First Prime(p): %lu\n", p);
        printf("Second Prime(q): %lu\n", q);
        printf("Nonce: %lu\n\n", q);
    }

    // generate keys
    verboseMessage("------ Generating Keys ------");

    while (overflowCount < 3) {
        // if it does not overflow
        if (!__builtin_umull_overflow(p, q, (unsigned long *) &nonce)) {
            // while finding an unsuccessful key
            while (unsuccessfulKeyCount < 3) {
                // if unsuccessful
                if (!mr_make_keys(p, q, user)) {
                    q = primes[rand() % NUMBER_OF_PRIMES];
                    fprintf(stderr, "error: mr_make_keys: no keyset for <%lu, %lu>.\n", p, q);
                    if (VERBOSE) printf("No successful p & q found, finding new q...\n");
                    unsuccessfulKeyCount++;
                } else {
                    // free primes
                    free(primes);
                    foundInv = 1;
                    break;
                }
            }
            // no inverse found
            if (!foundInv) {
                fprintf(stderr, "error: mr_make_keys: failed to generate keyset.\n");
                verboseMessage("------ FAILURE ------");
                // free primes
                free(primes);
                exit(EXIT_FAILURE);
            }
            break;
        } else {
            // overflows, finds new p & q, & increases overflowCount
            fprintf(stderr, "error: pq product overflow result '%lu' (0x%lx)\n", p * q, p * q);
            p = rand() % NUMBER_OF_PRIMES;
            q = rand() % NUMBER_OF_PRIMES;
            overflowCount++;
        }
    }
    // no inverse found
    if (!foundInv) {
        fprintf(stderr, "error: mr_make_keys: overflow. no keyset for <%lu, %lu>.\n", p, q);
        verboseMessage("------ FAILURE ------");
        free(primes);
        exit(EXIT_FAILURE);
    } else {
        verboseMessage("------ SUCCESS ------");
        exit(EXIT_SUCCESS);
    }
}
