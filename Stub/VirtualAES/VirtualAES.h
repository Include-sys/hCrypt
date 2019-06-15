#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define AES_RPOL    0x011b // reduction polynomial (x^8 + x^4 + x^3 + x + 1)
#define AES_GEN     0x03   // gf(2^8) generator  (x + 1)
#define AES_SBOX_CC 0x63   // S-Box C constant

#define KEY_128 (128/8) //strong
#define KEY_192 (192/8) //stronger
#define KEY_256 (256/8) //heavy duty

#define aes_mul(a, b) ((a)&&(b)?g_aes_ilogt[(g_aes_logt[(a)]+g_aes_logt[(b)])%0xff]:0)
#define aes_inv(a)  ((a)?g_aes_ilogt[0xff-g_aes_logt[(a)]]:0)
#define min(a, b) ((a) < (b) ? (a) : (b))

#define BLOCK_SIZE (128/8) //size of block

typedef struct {
	unsigned char state[4][4];
	int kcol;
	size_t rounds;
	unsigned long keysched[0];
} aes_ctx_t;

typedef unsigned long long u64;
typedef unsigned char uchar;

class virtualAES
{
public:
	static void initialize();
	/*ECB Block cipher mode (max 16chars)*/
	static void encrypt(aes_ctx_t *ctx, unsigned char input[16], unsigned char output[16]);
	static void decrypt(aes_ctx_t *ctx, unsigned char input[16], unsigned char output[16]);

	/*CTR Block cipher mode (must be dividible by 16)*/
	static void encrypt_ctr(aes_ctx_t *ctx, uchar *input, uchar *output, size_t len, u64 nonce);
	static void decrypt_ctr(aes_ctx_t *ctx, uchar *input, uchar *output, size_t len, u64 nonce);

	static aes_ctx_t *allocatectx(unsigned char *key, size_t keyLen);
	static void rand_nonce(u64 *nonce);

	static void strtohex(unsigned char const* pucCharStr, char* pszHexStr, int iSize);
	static void hextostr(char const* pszHexStr, unsigned char* pucCharStr, int iSize);

private:
	static unsigned char g_aes_logt[256], g_aes_ilogt[256];
	static unsigned char g_aes_sbox[256], g_aes_isbox[256];

	static inline unsigned long aes_subword(unsigned long w);
	static inline unsigned long aes_rotword(unsigned long w);

	static void aes_keyexpansion(aes_ctx_t *ctx);
	static inline unsigned char aes_mul_manual(unsigned char a, unsigned char b); // use aes_mul instead

	static void aes_subbytes(aes_ctx_t *ctx);
	static void aes_shiftrows(aes_ctx_t *ctx);
	static void aes_mixcolumns(aes_ctx_t *ctx);
	static void aes_addroundkey(aes_ctx_t *ctx, int round);
	static void aes_invsubbytes(aes_ctx_t *ctx);
	static void aes_invshiftrows(aes_ctx_t *ctx);
	static void aes_invmixcolumns(aes_ctx_t *ctx);
};

