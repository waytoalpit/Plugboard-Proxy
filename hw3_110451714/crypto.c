#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE];  
}; 

AES_KEY key; 
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;	 

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
	
    memset(state->ivec + 8, 0, 8);

    memcpy(state->ivec, iv, 8);
}

void fencrypt(char* in_data, char* out_data, char* iv, int size){ 

	const unsigned char* enc_key="1234567812345678";
	
	if(!memcpy(iv, iv,AES_BLOCK_SIZE)){
        fprintf(stderr, "Could not set iv.");
        exit(1);    
    }
    
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0){
        fprintf(stderr, "Could not set encryption key.");
        exit(1); 
    }
	
	init_ctr(&state, iv);
	
	AES_ctr128_encrypt(in_data, out_data, size , &key, state.ivec, state.ecount, &state.num);
}
	
void fdecrypt(char* in_data, char* out_data, char* iv, int size)
{	
    const unsigned char* enc_key="1234567812345678";
	
	if(!memcpy(iv, iv,AES_BLOCK_SIZE)){
        fprintf(stderr, "Could not set iv.");
        exit(1);    
    }
	
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0){
        fprintf(stderr, "Could not set decryption key.");
        exit(1);
    }

    init_ctr(&state, iv);
	
	AES_ctr128_encrypt(in_data, out_data, size , &key, state.ivec, state.ecount, &state.num);
}
