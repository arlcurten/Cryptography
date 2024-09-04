/*  ======================================================================== *
	https://github.com/YunJinHan/Cryptography/tree/master/XTS-AES

    and modified by TC Wei, Nov. 2023
 *  ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "AES.h"

#define BLOCK_SIZE 16  // BLOCK_SIZE = BLOCK_WIDTH * BLOCK_HEIGHT
#define BLOCK_WIDTH 4 
#define BLOCK_HEIGHT 4


static const uint8_t ori_sbox[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

static const uint8_t rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };

static const uint8_t matrix[16] = { 
    	0x02, 0x03, 0x01, 0x01, 
		0x01, 0x02, 0x03, 0x01,
		0x01, 0x01, 0x02, 0x03,
		0x03, 0x01, 0x01, 0x02 };

static const uint8_t inv_matrix[16] = { 
		0x0E, 0x0B, 0x0D, 0x09,
		0x09, 0x0E, 0x0B, 0x0D,
		0x0D, 0x09, 0x0E, 0x0B,
		0x0B, 0x0D, 0x09, 0x0E };


// Additional Fuction - Galois field multiplication.
BYTE GF_Mutiplication(uint8_t num,BYTE data){
    int i;
    BYTE tmp = 0;
    BYTE mask = 0x01;

    for (i = 0;i < num;i ++){
        if (num & mask){
            tmp ^= data;
        }
        if (data & 0x80){
            data = (data << 1) ^ 0x1b;
        } else {
            data <<= 1;
        }
        mask <<= 1;
    }
    return tmp;
}// Galois field mutiplication function.



/* <Key scheduling function>
 *
 * key: 16-byte key to perform key scheduling
 * roundKey: Space to contain the (Nr+1) round key that is the result of key scheduling
 * key_size_Byte: key size (128/192/256) in bytes (16/24/32)
 * ROUNDKEY_SIZE: size of roundKey (176/312/480)
 */
void expandKey(BYTE *key, BYTE *roundKey, int key_size_Byte, int ROUNDKEY_SIZE){

    int i,j,wi,r,roundKey_filled;
    int KEY_WIDTH = key_size_Byte/BLOCK_HEIGHT, KEY_HEIGHT = BLOCK_HEIGHT;
	BYTE tmp,gkey[KEY_HEIGHT];
    BYTE tmp_key[KEY_WIDTH][KEY_HEIGHT], temp_key_column[KEY_HEIGHT];
    // tmp: BYTE bariable for byte shift(swap)
    // gkey: W[k-1], the "final Word" of previous round(row)
    // temp_key: save temporary result in key shape(size) of 4x4/6x4/8x4 bytes

    //-- Copy original key to temp_key --//
    for (i=0; i<KEY_WIDTH; i++){
		for (j=0; j<KEY_HEIGHT; j++){
			tmp_key[i][j] = *(key + i*4 + j);
		}
	}

    //-- The 1st row Words are the original key itself --//
	roundKey_filled = 0;  // roundKey index (counter)
    for (i=0; i<KEY_WIDTH; i++){
		for (j=0; j<KEY_HEIGHT; j++){
			*(roundKey + (roundKey_filled++)) = tmp_key[i][j];  //-- Store calculated key into RoundKey
		}
	}

    //-- Process followings in Words(BLOCK_HEIGHT), Word row by Word row --//
    r = 1;
    // printf("ROUNDKEY_SIZE=%d\n", ROUNDKEY_SIZE);  // for debugging
    for(wi = KEY_WIDTH; wi < (ROUNDKEY_SIZE / KEY_HEIGHT); wi+=KEY_WIDTH){  // i: Word index started from the 2nd row
        //-- Processing W[k] --//
        if( (i % KEY_WIDTH) == 0){
            for (j = 0; j < KEY_HEIGHT; j++){
			    gkey[j] = tmp_key[KEY_WIDTH-1][j];
		    }
            //-- g() --//
            // Shift left 1 bit
            tmp = gkey[0];
            for (j = 0; j < (KEY_HEIGHT - 1); j++){
                gkey[j] = gkey[j + 1];
            }
            gkey[KEY_HEIGHT - 1] = tmp;
            // Sub ori_sbox
            for (j = 0; j < KEY_HEIGHT; j++){
                gkey[j] = ori_sbox[ gkey[j] ];
            }
            // XOR with rcon matrix
            gkey[0] ^= rcon[r++];  // r: R constant (RC[]) index, starting from 1
            // XOR gkey
            for (j = 0; j < KEY_HEIGHT; j++){
                tmp_key[0][j] ^= gkey[j];  // W[k] = g(W[k-1]) XOR W[k-KEY_WIDTH]
            }
        }
        //-- Processing W[k+1] to W[k+KEY_WIDTH-1] --//
        for (i = 1; i < KEY_WIDTH; i++){  // generate W[k+1] to W[k+3]
            for (j = 0; j < KEY_HEIGHT; j++){
                if(key_size_Byte==32 && i==4){  // special case: subKey here in 256 bits
                    temp_key_column[j] = ori_sbox[ tmp_key[i-1][j] ];
                }
                else{
                    temp_key_column[j] = tmp_key[i-1][j];
                }
                tmp_key[i][j] ^= temp_key_column[j];
            }
        }
        //-- Store calculated key into RoundKey --//
        for (i = 0; i < KEY_WIDTH; i++){
            for (j = 0; j < KEY_HEIGHT; j++){
				*(roundKey + (roundKey_filled++)) = tmp_key[i][j];
			}
		}
    }
    // //-- Print out for debugging --//
    // roundKey_filled = 0;
    // for (i = 0; i < (ROUNDKEY_SIZE/4); i++){  // Words index
    //     printf("Word# %2d  ", i);
    //     for (j = 0; j < KEY_HEIGHT; j++){
    //         printf("%02x", *(roundKey + (roundKey_filled++)) );
    //     }
    //     printf("\n");
    // }
}


/* <SubBytes function>
 *
 * block: SubBytes 16-byte block to perform. 
 *        The execution results are immediately reflected in the corresponding array.
 * mode: SubBytes execution mode
 */
BYTE* subBytes(BYTE *block, int mode){

    int i;

    switch(mode){

        case ENC:
            for (i = 0;i < BLOCK_SIZE;i ++){
        		*(block + i) = ori_sbox[ *(block + i) ];
        	}// SubByte ori_sbox.
            break;

        case DEC:
            for (i = 0;i < BLOCK_SIZE;i ++){
        		*(block + i) = inv_sbox[ *(block + i) ];
        	}// SubByte inv_sbox.
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}


/* <ShiftRows function>
 *
 * block: 16-byte block to perform ShiftRows on. 
 *        The execution results are immediately reflected in the corresponding array.
 * mode: ShiftRows execution mode
 */
BYTE* shiftRows(BYTE *block, int mode){ 

    int i,j,rep;
    BYTE tmp;

    switch(mode){

        case ENC:
            for (i = 1; i < BLOCK_SIZE/4;i ++){
                for (rep = i;rep >= 1;rep --){
                    tmp = *(block + i);
                    for (j = i; j < (i + BLOCK_SIZE - BLOCK_SIZE/4) ;j += 4){
                        *(block + j) = *(block + j + BLOCK_SIZE/4);
                    }
                    *(block + i + BLOCK_SIZE - BLOCK_SIZE/4) = tmp;
                }
            }
            // 1 left Shift 2nd Col, 2 left Shift 3rd Col, 3 left Shift 4th Col.
            break;

        case DEC:
            for (i = 1; i < BLOCK_SIZE/4;i ++){
                for (rep = i;rep >= 1;rep --){
                    tmp = *(block + i + BLOCK_SIZE - BLOCK_SIZE/4);
                    for (j = i + BLOCK_SIZE - BLOCK_SIZE/4; j >= i ;j -= 4){
                        *(block + j) = *(block + j - BLOCK_SIZE/4);
                    }
                    *(block + i) = tmp;
                }
            }
            // 1 right Shift 2nd Col, 2 right Shift 3rd Col, 3 right Shift 4th Col.
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}

/* <MixColumns function>
 *
 * block: 16-byte block on which to perform MixColumns. 
 *        The execution results are immediately reflected in the corresponding array.
 * mode: Execution mode of MixColumns
 */
BYTE* mixColumns(BYTE *block, int mode){    

    int i,j,k;

    BYTE tmp[16] = {0,};
    BYTE tmp2[4][4];

    for (i=0;i<4;i++){ for (j=0;j<4;j++){ tmp2[i][j] = *(block+i*4+j); } }
    for (i=0;i<4;i++){ for (j=0;j<4;j++){ *(block+i*4+j) = tmp2[j][i]; } }

    switch(mode){

        case ENC:
            for (i = 0;i < BLOCK_SIZE/4 ;i ++){
                for (j = 0;j < BLOCK_SIZE/4 ;j ++){
                    for (k = 0;k < BLOCK_SIZE/4 ;k ++){
                        tmp[ i*4 +j ] ^= GF_Mutiplication(matrix[ i*4 + k ],*(block + k*4 + j));
                    }
                }
            }// Galois field mutiplication data with matirx.
            break;

        case DEC:
            for (i = 0;i < BLOCK_SIZE/4 ;i ++){
                for (j = 0;j < BLOCK_SIZE/4 ;j ++){
                    for (k = 0;k < BLOCK_SIZE/4 ;k ++){
                        tmp[ i*4 +j ] ^= GF_Mutiplication(inv_matrix[ i*4 + k],*(block + k*4 + j));
                    }
                }
            }// Galois field mutiplication data with inv_matirx.
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }

    for (i=0;i<4;i++){ for (j=0;j<4;j++){ tmp2[i][j] = tmp[i*4+j]; } }
    for (i = 0;i <BLOCK_SIZE/4 ;i ++){
        for (j = 0;j < BLOCK_SIZE/4 ;j ++){
            *(block + i*4 + j) = tmp2[j][i];
        }
    }// change origin block to calculated tmp.    
    
    return block;
}

/*  <AddRoundKey function>
 * block: 16-byte block on which to perform AddRoundKey. 
 *        The execution results are reflected in the corresponding array.
 * rKey: 16-byte round key to perform AddRoundKey on.
 */
BYTE* addRoundKey(BYTE *block, BYTE *rKey){
    int i,j;
	for (i = 0 ; i < BLOCK_SIZE/4 ; i++){
		for (j = i ; j < BLOCK_SIZE ; j+=4){
			*(block + j) ^= *(rKey + j);
		}
	}// XOR Calculate origin block data with RoundKey.
    
    return block;
}


BYTE* encrypt(BYTE *plain, BYTE *key, int key_size_Byte){
    int round;
    int Nr;

    switch(key_size_Byte){
        case 16:  Nr = 10;  break;  // 128
        case 24:  Nr = 12;  break;  // 192
        case 32:  Nr = 14;  break;  // 256
        default:  Nr = 0;   break;
    };
    // printf("Nr=%d\n",Nr);  // for debugging
    
    int rkeySize = BLOCK_SIZE * (Nr+1);  // 176/208/240 bytes (44/52/60 Words), Nr-> number of rounds
    // make it round to multiple of key_size (16/24/32), to fit expandKey() design
    int ROUNDKEY_SIZE = (rkeySize % key_size_Byte == 0)? rkeySize : ((rkeySize/key_size_Byte)+1) * key_size_Byte;
    BYTE roundKey[ROUNDKEY_SIZE];

    for (round = 0; round <= Nr; round ++){
    	// printf("round = %d\n", round);  // for debugging
        if (round == 0){ // initial round of encryption.
			expandKey(key,roundKey,key_size_Byte, ROUNDKEY_SIZE);
            addRoundKey(plain,roundKey);
    	} else if (round == Nr){ // final round of encryption.
    		subBytes(plain,ENC);
    		shiftRows(plain,ENC);
    		addRoundKey(plain,roundKey + round*BLOCK_SIZE);
    	} else { // other main rounds of encryption.
	    	subBytes(plain,ENC);
	    	shiftRows(plain,ENC);
	    	mixColumns(plain,ENC);
	    	addRoundKey(plain,roundKey + round*BLOCK_SIZE);
	    }
    }
    return plain;
}

BYTE* decrypt(BYTE *cipher, BYTE *key, int key_size_Byte){
    int round;
    int Nr;

    switch(key_size_Byte){
        case 16:  Nr = 10;  break;  // 128
        case 24:  Nr = 12;  break;  // 192
        case 32:  Nr = 14;  break;  // 256
        default:  Nr = 0;   break;
    };
    // printf("Nr=%d\n",Nr);  // for debugging

    int rkeySize = BLOCK_SIZE * (Nr+1);  // 176/208/240 bytes (44/52/60 Words), Nr-> number of rounds
    // make it round to multiple of key_size (16/24/32), to fit expandKey() design
    int ROUNDKEY_SIZE = (rkeySize % key_size_Byte == 0)? rkeySize : ((rkeySize/key_size_Byte)+1) * key_size_Byte;
    BYTE roundKey[ROUNDKEY_SIZE];
    
    for (round = Nr; round >=0; round --){
        // printf("round = %d\n", round);  // for debugging
    	if (round == 0){ // final round of encryption.
    		shiftRows(cipher,DEC);
    		subBytes(cipher,DEC);
    		addRoundKey(cipher,roundKey);
    	} else if (round == Nr){ // initial round of encryption.
    		expandKey(key,roundKey,key_size_Byte, ROUNDKEY_SIZE);
    		addRoundKey(cipher,roundKey + round*BLOCK_SIZE);
    	} else { // other main rounds of encryption.
    		shiftRows(cipher,DEC);
    		subBytes(cipher,DEC);
    		addRoundKey(cipher,roundKey + round*BLOCK_SIZE);
    		mixColumns(cipher,DEC);
    	}
    }
    return cipher;
}



void AES(BYTE *plain, BYTE *cipher, BYTE *key, int mode, int key_size){
    BYTE *tmp;  
    int key_size_Byte = key_size/8;
    int i;

    if(key_size!=128 && key_size!=192 && key_size!=256){
		fprintf(stderr, "Invalid key size!\n");
        exit(1);
	}

    if(mode == ENC){
        tmp = encrypt(plain, key, key_size_Byte);
        for (i = 0; i < BLOCK_SIZE ; i ++){
        	*(cipher + i) = *(tmp + i);
        }// copy tmp blocks to ciper blocks.

    }else if(mode == DEC){
        tmp = decrypt(cipher, key, key_size_Byte);
        for (i = 0; i < BLOCK_SIZE ; i ++){
        	*(plain + i) = *(tmp + i);
        }// copy tmp blocks to plain blocks.
        
    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}
