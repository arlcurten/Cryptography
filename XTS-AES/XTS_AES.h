
#define ENC 1 
#define DEC 0 

typedef unsigned char BYTE;

void XTS_AES(BYTE *plain, BYTE *cipher, uint8_t *iv, unsigned int size, BYTE* key, int mode, int key_size);