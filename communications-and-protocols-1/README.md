
## Needed head library:
stdio.h, stdlib.h string.h ,openssl/sha.h , openssl/rsa.h ,openssl/pem.h , blockchain.h ,stdbool.h

# Need to define : 
 - MAX_BLOCKS=1000 , MAX_TRANSACTIONS 100, HASH_SIZE 32 , PUBLIC_KEY_SIZE 128 , Wallet struct
# Prototype function :
 - calculate_block_hash , calculate_transaction_hash, print_blockchain_info,load_wallet_public_key, get_wallet_balance,calculate_wallet_balance,load_public_key, b64_decode, 
 verify_transaction

## Using  Function
 void calculate_block_hash(Block *block):   <br> <br> Declare function"calculate_block_hash" that:
-  takes a pointer named Block struct as parameter
- Declare array character names data with size 1024
- sends formatted output "%d%d%s" to a by using array data.
- use c library function memset to set current hash to 0 by copied 0 to block_hash    
- compute hash using SHA256 (used for cryptographic security)


 void calculate_transaction_hash(Transaction *transaction, char *hash):  <br> <br> Function to calculate SHA256 hash of a transaction:
- use c library function memset to set current hash to 0 by copied 0 to hash    
- compute hash of transaction using SHA256 (cryptographic security)


void print_blockchain_info(Blockchain *blockchain): <br><br> Function to print blockchain information: 
- that take ablockchain pointer 
- print Number of blocks (blockchain length)
- For each block : print block number,num of transactions,pervious hash ,current hash
- and then print Total number of transactions 

## Task 2 : Display a balance <br><br>
Add wallet functionality by  load a public key from the filessystem. This 1024-bit public key is both the identifier for the wallet and decrypt the signature. produce a wallet balance based on all of the transfers into and out of wallet.

void load_wallet_public_key(char *filename, RSA **public_key): <br><br> 
function "load_wallet_public_key" takes parmeters filneame (path) pointer and pointer of pointer public key :
- use fopen function to read fILE and set to pointer named (fb) *fp = fopen(filename, "r");
- check if fp is empty then print ("error could not open public key")and exit
- using function "PEM_read_RSA_PUBKEY" from openssl library to read public key from file (fp)
    and set to pointer *public_key 
- check if *public_key equal NULL or empty then print "that is Error in coludnot read public key"
    and exit.
- finally close file fp using function fclose();

int calculate_wallet_balance(Blockchain* blockchain, const char* wallet_id): <br> <br> 

Using "calculate_wallet_balance" function take parameters pointer nameed* blockchain and wallet_id:

- intialize var named balance to be returned aftre calculate>
- intialize public-key cryptosystem named rsa make aload public key for wallet id 
- check if rsa is null or empty then we have "error couldn't load public key"
- else for each block and transction: <br>
&nbsp;&nbsp;-make compare using function strcmp <br>
            - between receiver public key, wallet_id then add to the wallet<br>
          - between sender public key, wallet_id then subtract funds from the wallet<br>
        -verify the signature<br> 
        -calculate transaction hash print "Warning: invalid signature"<br>
        - if rsa (public-key cryptosystem) not verify <br>
     - clear rsa<br>
    - return var named balance<br>
    
RSA* load_public_key(const char* filename): <br><br>

    function "load_public_key" takes parmeters filneame (path) pointer>:
- use fopen function to read fILE and set to pointer named (fb)
- check if fp is empty then print ("error could not open public key")and exit
- using function "PEM_read_RSA_PUBKEY" from openssl library to read public key from file (fp)
    and set to pointer *rsa


double get_wallet_balance(Wallet *wallet, Blockchain *blockchain): <br><br>

   use function "get_wallet_balance" that take Walet and blockchain pointers and return double balance:
  
- intilize a double variable name balance 
- for each block and transatcion : 
        - make compare using function strcmp : 
          - between receiver public key, wallet public key then add to the balance
          - between sender public key, wallet public key then subtract funds from the balance
- return balance 
    
       
## Task 3 : Authenticating transactions <br><br>

Extend wallet program to check each transaction for authenticity. 
by decrypting the signature using the sender’s public key. 

bool verify_transaction(char *transaction, char *signature, char *public_key_file): <br><br>

    To check ecrypted signature should be requal to the hash or not we using function "verify_transaction" by take transaction, signature and public_key_file:

- we need to open file using fopen function and set to pointer (f) and if not found display "file not open" 
- Read the public key from file
- close file 
- check if public key not exisit display error "PEM_read_RSA_PUBKEY"
- Decode the signature from Base64 by using fucition b64_decode if not decode free public key and return value false.
- Decrypt the signature using the public key .
- Calculate the hash of the transactionand if Null willterminate the hash string.
- Compare the decrypted signature and the transaction hash, and if the signature does not match the transaction hash return false else return true.
    


int b64_decode(const char *input, size_t input_len, unsigned char **output, size_t *output_len) : <br><br>

function b64_decodetake 4 parmeter input pointer and length of it , pointer ofoutput pointer and output length:
 
 - declare char array have different charachters.
 - Check input and output pointers not null 
 - Allocate output buffer
 - Decode input buffer
 - calculate and set output 



## Calling main
    task 1 and 2 : <br><br>

 - Create blockchain 
 - print blockchain

    task3 : <br><br>
 - define transaction, signature,public_key_file
 - Populate blocks with dummy data
 - read bloack and check is valid or not
        



![WhatsApp_Image_2023-04-09_at_9.51.07_PM](/uploads/b7a86c5fbc415ad23be4b9bfff488866/WhatsApp_Image_2023-04-09_at_9.51.07_PM.jpeg)

