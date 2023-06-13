#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "blockchain.h"
#include <stdbool.h>

#define MAX_BLOCKS 1000
#define MAX_TRANSACTIONS 100
#define HASH_SIZE 32
#define PUBLIC_KEY_SIZE 128 // 1024 bits / 8 bits per byte

typedef struct {
    char public_key[PUBLIC_KEY_SIZE];
    double balance;
} Wallet;

void calculate_block_hash(Block *block);
void calculate_transaction_hash(Transaction *transaction, char *hash);
void print_blockchain_info(Blockchain *blockchain);

void load_wallet_public_key(char *filename, RSA **public_key);
double get_wallet_balance(Wallet *wallet, Blockchain *blockchain);
int calculate_wallet_balance(Blockchain* blockchain, const char* wallet_id);

RSA* load_public_key(const char* filename);
int b64_decode(const char *input, size_t input_len, unsigned char** output, size_t *output_len);
bool verify_transaction(char *transaction, char *signature, char *public_key_file);

// Function to calculate SHA256 hash of a block
void calculate_block_hash(Block *block) {   // Declare function that takes a pointer to a Block struct as parameter
    char data[1024];   // Declare function that takes a pointer to a Block struct as parameter
    sprintf(data, "%d%d%s", block->block_num, block->num_transactions,block->prev_block_hash);// Format and concatenate block data
    memset(block->block_hash, 0, sizeof(block->block_hash)); // set current hash to 0
    SHA256((const unsigned char*)data, strlen(data), (unsigned char*)block->prev_block_hash); // compute hash
}

// Function to calculate SHA256 hash of a transaction
void calculate_transaction_hash(Transaction *transaction, char *hash) {
    memset(hash, 0, sizeof(hash)); // set hash to 0
    SHA256((const unsigned char*)transaction, sizeof(Transaction), (unsigned char*)hash); // compute hash
}

// Function to print blockchain information
void print_blockchain_info(Blockchain *blockchain) {
    printf("Number of blocks: %d\n", blockchain->length);
    int total_transactions = 0;
    for (int i = 0; i < blockchain->length; i++) {
        total_transactions += blockchain->blocks[i].num_transactions;
        printf("Block #%d:\n", blockchain->blocks[i].block_num);
        printf("Number of transactions: %d\n", blockchain->blocks[i].num_transactions);
        printf("Previous hash: %s\n", blockchain->blocks[i].prev_block_hash);
        printf("Current hash: %s\n", blockchain->blocks[i].block_hash);
        for (int j = 0; j < blockchain->blocks[i].num_transactions; j++) {
            char hash[65];
            calculate_transaction_hash(&blockchain->blocks[i].transactions[j], hash);
            printf("Transaction #%d hash: %s\n", j+1, hash);
        }
    }
    printf("Total number of transactions: %d\n", total_transactions);
}

void load_wallet_public_key(char *filename, RSA **public_key) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error: Could not open public key file %s\n", filename);
        exit(1);
    }
    *public_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if (*public_key == NULL) {
        printf("Error: Could not read public key file %s\n", filename);
        exit(1);
    }
    fclose(fp);
}

int calculate_wallet_balance(Blockchain* blockchain, const char* wallet_id) {
    int balance = 0;
    RSA* rsa = load_public_key(wallet_id);
    if (rsa == NULL) {
        fprintf(stderr, "Error: could not load public key for wallet %s\n", wallet_id);
        return 0;
    }
    for (int i = 0; i < blockchain->length; i++) {
        for (int j = 0; j < blockchain->blocks[i].num_transactions; j++) {
            //Transaction* tx = blockchain->blocks[i].transactions[j];
            if (strcmp(blockchain->blocks[i].transactions[j].receiver_public_key, wallet_id) == 0) {
                // add funds to the wallet
                balance += blockchain->blocks[i].transactions[j].amount;
            }
            if (strcmp(blockchain->blocks[i].transactions[j].sender_public_key, wallet_id) == 0) {
                // subtract funds from the wallet
                balance -= blockchain->blocks[i].transactions[j].amount;
                // verify the signature
                char hash[HASH_SIZE];
                calculate_transaction_hash(&blockchain->blocks[i].transactions[j], hash);
                if (RSA_verify(NID_sha256, (unsigned char*)hash, HASH_SIZE, (unsigned char*)blockchain->blocks[i].transactions[j].signature, RSA_size(rsa), rsa) != 1) {
                    fprintf(stderr, "Warning: invalid signature in transaction %d of block %d\n", j+1, i+1);
                }
            }
        }
    }
    RSA_free(rsa);
    return balance;
}

RSA* load_public_key(const char* filename) {
    RSA* rsa = NULL;
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        return NULL;
    }
    rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        fprintf(stderr, "Error: could not read public key from file %s\n", filename);
    }
    return rsa;
}

double get_wallet_balance(Wallet *wallet, Blockchain *blockchain) {
    double balance = 0.0;
    for (int i = 0; i < blockchain->length; i++) {
        Block *block = &blockchain->blocks[i];
        for (int j = 0; j < block->num_transactions; j++) {
            //Transaction tx = block->transactions[j];
            if (strcmp(block->transactions[j].receiver_public_key, wallet->public_key) == 0) {
                balance += block->transactions[j].amount;
            }
            if (strcmp(block->transactions[j].sender_public_key, wallet->public_key) == 0) {
                balance -= block->transactions[j].amount;
            }
        }
    }
    return balance;
}

bool verify_transaction(char *transaction, char *signature, char *public_key_file) {
    // Read the public key from file
    FILE *f = fopen(public_key_file, "rb");
    if (!f) {
        perror("file not open");
        return false;
    }
    RSA *public_key = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!public_key) {
        perror("PEM_read_RSA_PUBKEY");
        return false;
    }

    // Decode the signature from Base64
    unsigned char *signature_decoded = NULL;
    size_t signature_decoded_len = 0;
    if (b64_decode((const char *) signature, strlen(signature), &signature_decoded, &signature_decoded_len) != 0) {
        perror("b64_decode");
        RSA_free(public_key);
        return false;
    }

    // Decrypt the signature using the public key
    unsigned char decrypted_signature[SHA256_DIGEST_LENGTH];
    int decrypted_signature_len = RSA_public_decrypt(RSA_size(public_key), (unsigned char *) signature_decoded,
                                                     decrypted_signature, public_key, RSA_PKCS1_PADDING);
    free(signature_decoded);

    // Calculate the hash of the transaction
    unsigned char transaction_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *) transaction, strlen(transaction), transaction_hash);
    transaction_hash[SHA256_DIGEST_LENGTH - 1] = '\0'; // Null-terminate the hash string

    // Compare the decrypted signature and the transaction hash
    if (decrypted_signature_len != SHA256_DIGEST_LENGTH || memcmp(decrypted_signature, transaction_hash, SHA256_DIGEST_LENGTH) != 0) {
        RSA_free(public_key);
        return false; // The signature does not match the transaction hash
    }
    else{
        RSA_free(public_key);
        return true;
    }
}

int b64_decode(const char *input, size_t input_len, unsigned char **output, size_t *output_len) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Check input and output pointers
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    // Allocate output buffer
    size_t buf_size = input_len * 3 / 4;
    *output = (unsigned char*) malloc(buf_size);
    if (*output == NULL) {
        return -1;
    }
    *output_len = 0;

    // Decode input buffer
    unsigned char ch1, ch2, ch3, ch4;
    unsigned char *out = *output;
    for (size_t i = 0; i < input_len; i += 4) {
        ch1 = strchr(base64_chars, input[i]) - base64_chars;
        ch2 = strchr(base64_chars, input[i+1]) - base64_chars;
        ch3 = input[i+2] == '=' ? 0 : strchr(base64_chars, input[i+2]) - base64_chars;
        ch4 = input[i+3] == '=' ? 0 : strchr(base64_chars, input[i+3]) - base64_chars;

        if (ch1 == -1 || ch2 == -1 || ch3 == -1 || ch4 == -1) {
            free(*output);
            return -1;
        }

        *out++ = (ch1 << 2) | (ch2 >> 4);
        *output_len += 1;

        if (input[i+2] != '=') {
            *out++ = ((ch2 & 0xf) << 4) | (ch3 >> 2);
            *output_len += 1;
        }

        if (input[i+3] != '=') {
            *out++ = ((ch3 & 0x3) << 6) | ch4;
            *output_len += 1;
        }
    }
    return 0;
}

int main() {

    //task 1 and 2 
    // Create blockchain
    Blockchain blockchain;
    blockchain.length = 3;
    blockchain.blocks = malloc(sizeof(Block)*blockchain.length);
    
    //task3
    char transaction[] = "MIGJAoGBAKp==";
    char signature[] = "MIGJAoGBAKp=="; //"Zm9vYmFyCg=="; // Base64-encoded signature
    char public_key_file[] = "keys/0/public_key.pem";

    // Populate blocks with dummy data
    //task 3 
    for (int i = 0; i < blockchain.length; i++) {
        Block b;
        b.block_num = i+1;
        b.num_transactions = 2;
        //printf("Hello World %u\n", i);
        printf("Transaction #%u.1\n", i+1);
        printf("Transaction #%d.2\n", i+1);
        calculate_block_hash(&b); // calculate current hash
        blockchain.blocks[i] = b;
        bool is_vald = verify_transaction(transaction,signature,public_key_file);
        if (is_vald){
            printf("Transaction is valid.\n");
        } 
        else {
            printf("Transaction is invalid.\n");    
        }
       
    }

        return 0;
} 



#include <ctype.h>

