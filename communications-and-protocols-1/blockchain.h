#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>

#define MAX_TRANSACTIONS_PER_BLOCK 100

typedef struct {
    uint8_t sender_public_key[128];
    uint8_t receiver_public_key[128];
    double amount;
    uint8_t signature[128];
} Transaction;

typedef struct {
    uint32_t block_num;
    uint32_t num_transactions;
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK];
    uint8_t prev_block_hash[32];
    uint8_t block_hash[32];
} Block;

typedef struct {
    uint32_t length;
    Block *blocks;
} Blockchain;

void hash_block(Block *block);
void hash_transaction(Transaction *transaction);
void add_transaction(Block *block, Transaction *transaction);
void add_block(Blockchain *blockchain, Block *block);

#endif
