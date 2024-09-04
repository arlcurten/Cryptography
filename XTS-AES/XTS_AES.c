/*  ======================================================================== *
	https://github.com/YunJinHan/Cryptography/tree/master/XTS-AES

	and modified by TC Wei, Nov. 2023
 *  ======================================================================== */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "XTS_AES.h"
#include "AES.h"

#define BLOCK_SIZE 16  // (byte numbers) // 16 bytes *8 = 128 bits
uint8_t iv2[BLOCK_SIZE];

// Additional Generator function in GF(2^128) to make tweakable variable.
void GF_Multiplication_xts(uint8_t *T){

    uint32_t x;
    uint8_t t, tt;
    
    for (x = t = 0;x < BLOCK_SIZE;x ++) {
        tt = *(T + x) >> 7;
        *(T + x) = ((*(T + x) << 1) | t) & 0xFF;
        t = tt;
    }
    if (tt) {
        *(T) ^= 0x87;
    } 
}
// Generator function in GF(2^128).


/* <128-bit XTS_AES encryption/decryption function>
  *
  * A function that encrypts the plaintext if the mode is ENC, and decrypts the ciphertext if the mode is DEC.
  *
  * [ENC mode]
  * plain:  Plain text byte array
  * cipher: A byte array that will contain the cipher result (ciphertext). The calling user allocates memory in advance and passes it as a parameter.
  * iv: initial vector for XTS mode
  * size:   Plaintext size (byte numbers)
  * key:    128*2/192*2/256*2-bit encryption key. The first half are key1, and the second half are key2.
  * key_size: 128, 192, 256.
  *
  * [DEC mode]
  * plain:  Byte array containing the results (plain text). The calling user allocates memory in advance and passes it as a parameter.
  * cipher: ciphertext byte array
  * iv: initial vector for XTS mode
  * size:   Ciphertext size (byte numbers)
  * key:    128*2/192*2/256*2-bit encryption key. The first half are key1, and the second half are key2.
  * key_size: 128, 192, 256.
 */
void XTS_AES(BYTE *plain, BYTE *cipher, uint8_t *iv, unsigned int size, BYTE* key, int mode, int key_size){

	int i,j,tmp;
	BYTE *T = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);
    BYTE *T2 = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);
	BYTE *PP = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);
    BYTE *CC = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);

    for (i = 0;i < BLOCK_SIZE;i ++){
        *(iv2 + i) = *(iv + i);
    } // copy initial vector to use ENC / DEC.

	if(key_size!=128 && key_size!=192 && key_size!=256){
		fprintf(stderr, "Invalid key size!\n");
        exit(1);
	}

	AES(iv2, T, key+(key_size/8), ENC, key_size);
	// create initial T with iv. ( ∂(0) == E(key2)(iv,T) )
    
    if(mode == ENC){

    	for (i = 0;i < size/BLOCK_SIZE;i ++){

    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(PP + j) = plain[ i*BLOCK_SIZE + j ] ^ *(T + j);
    		}// create PP blocks.
    		AES(PP,CC,key,ENC,key_size);
    		// create CC blocks.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			cipher[ i*BLOCK_SIZE + j ] = *(CC + j) ^ *(T + j);
    		}// create ciper blocks.
    		GF_Multiplication_xts(T);
    		// create tweakable block.
    	}// when plain text is 16 multiples, it's over.

    	if (size%BLOCK_SIZE != 0){
    		// cipertext stealing.

    		for (j = 0;j < (size%BLOCK_SIZE);j ++){
    			cipher[ i*BLOCK_SIZE + j ] = cipher[ (i-1)*16 + j ];
    			*(PP + j) = *(T + j) ^ plain[ i*BLOCK_SIZE + j ];
    		}// shift and XOR.
    		for (j = size%BLOCK_SIZE;j < BLOCK_SIZE;j ++){
    			*(PP + j) = *(T + j) ^ cipher[ (i-1)*BLOCK_SIZE + j ];
    		}// create Additional PP blocks.
    		AES(PP,CC,key,ENC,key_size);
    		// create Additional CC blocks.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			cipher[ (i-1)*BLOCK_SIZE + j ] = *(T + j) ^ *(CC + j);
    		}// create Additional ciper blocks.

    	}// when plain text length is not 16 multiples, it's done.
    	
    }else if(mode == DEC){

    	int check = (size%BLOCK_SIZE==0) ? 0 : 1; 
    	// judge variable that size%BLOCK_SIZE is 0 or is not 0.
    	// check == 0 is size%BLOCK_SIZE == 0.
    	// check == 1 is size%BLOCK_SIZE != 0.
    	for (i = 0;i < size/BLOCK_SIZE;i ++){

    		if (i == size/BLOCK_SIZE - 1 && check) {
                tmp = size/BLOCK_SIZE - 1;
                break;
            }
    	    // when ciper text length is not 16 multiples.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(CC + j) = cipher[ i*BLOCK_SIZE + j ] ^ *(T + j);
    		}// create PP blocks.
			AES(PP,CC,key,DEC,key_size);
			// create CC blocks.
			for (j = 0;j < BLOCK_SIZE;j ++){
				plain[ i*BLOCK_SIZE + j ] = *(PP + j) ^ *(T + j);
			}// create plain blocks.
			GF_Multiplication_xts(T);
    		// create tweakable block.
    	}

    	if (check) {
            // when ciper text length is not 16 multiples.
    		// cipertext stealing.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(T2 + j) = *(T + j);
    		}// copy tweakable block to tmp array.
    		GF_Multiplication_xts(T);
    		// create tweakable block.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(CC + j) = *(T + j) ^ cipher[ tmp*BLOCK_SIZE + j ];
    		}// create Additional ciper blocks.
    		AES(PP,CC,key,DEC,key_size);
    		// create CC blocks.
    		for (j = 0;j < size%BLOCK_SIZE;j ++){
    			plain[ (tmp + 1)*BLOCK_SIZE + j ] = *(T + j) ^ *(PP + j);
    			*(CC + j) = *(T2 + j) ^ cipher[ (tmp + 1)*BLOCK_SIZE + j ];
    		}// shift and XOR.
    		for (j = size%BLOCK_SIZE;j < BLOCK_SIZE;j ++){
    			*(CC + j) = *(T2 + j) ^ *(T + j) ^ *(PP + j);
    		}// create Additional ciper blocks.
    		AES(PP,CC,key,DEC,key_size);
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			plain[ tmp*BLOCK_SIZE + j ] = *(T2 + j) ^ *(PP + j);
    		}// create Additional PP blocks.
    	}

    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
    free(T);
    free(T2);
    free(PP);
    free(CC);
	/*********************************************** { 구현 14 종료 } ********************************************/
}
