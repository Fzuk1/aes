#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "main.h"
#include "aes.h"

/* STATIC VARIABLES */
static const char *sbox_string =
	"637c777bf26b6fc53001672bfed7ab76"
	"ca82c97dfa5947f0add4a2af9ca472c0"
	"b7fd9326363ff7cc34a5e5f171d83115"
	"04c723c31896059a071280e2eb27b275"
	"09832c1a1b6e5aa0523bd6b329e32f84"
	"53d100ed20fcb15b6acbbe394a4c58cf"
	"d0efaafb434d338545f9027f503c9fa8"
	"51a3408f929d38f5bcb6da2110fff3d2"
	"cd0c13ec5f974417c4a77e3d645d1973"
	"60814fdc222a908846eeb814de5e0bdb"
	"e0323a0a4906245cc2d3ac629195e479"
	"e7c8376d8dd54ea96c56f4ea657aae08"
	"ba78252e1ca6b4c6e8dd741f4bbd8b8a"
	"703eb5664803f60e613557b986c11d9e"
	"e1f8981169d98e949b1e87e9ce5528df"
	"8ca1890dbfe6426841992d0fb054bb16";

static const char *inv_sbox_string =
	"52096ad53036a538bf40a39e81f3d7fb"
	"7ce339829b2fff87348e4344c4dee9cb"
	"547b9432a6c2233dee4c950b42fac34e"
	"082ea16628d924b2765ba2496d8bd125"
	"72f8f66486689816d4a45ccc5d65b692"
	"6c704850fdedb9da5e154657a78d9d84"
	"90d8ab008cbcd30af7e45805b8b34506"
	"d02c1e8fca3f0f02c1afbd0301138a6b"
	"3a9111414f67dcea97f2cfcef0b4e673"
	"96ac7422e7ad3585e2f937e81c75df6e"
	"47f11a711d29c5896fb7620eaa18be1b"
	"fc563e4bc6d279209adbc0fe78cd5af4"
	"1fdda8338807c731b11210592780ec5f"
	"60517fa919b54a0d2de57a9f93c99cef"
	"a0e03b4dae2af5b0c8ebbb3c83539961"
	"172b047eba77d626e169146355210c7d";

/* STATIC FUNCTIONS */
static u8 sbox(u8 x) {
	char str[2] = {sbox_string[x*2], sbox_string[x*2+1]};
	u32 hex = (u32)strtol(str, NULL, 16);
	return (u8)hex;
}

static u8 inv_sbox(u8 x) {
	char str[2] = {inv_sbox_string[x*2], inv_sbox_string[x*2+1]};
	u32 hex = (u32)strtol(str, NULL, 16);
	return (u8)hex;
}

static u8 *state_from_bytes(char *data) {
	// 4 * 4 = 16 bytes (1 block)
	u8 *state = malloc(sizeof(char) * ROWS * NB);
	for (u32 c = 0; c < NB; c++) {
		for (u32 r = 0; r < ROWS; r++) {
			state[r * NB + c] = data[r + (4 * c)];
		}
	}
	return state;
}

static u32 word_from_bytes(u8 b1, u8 b2, u8 b3, u8 b4) {
	return
		((u32)b1 << 24) |
		((u32)b2 << 16) |
		((u32)b3 <<  8) |
		((u32)b4);
}

static u8 *bytes_from_word(u32 word) {
	u8 b1 = (u8)(word >> 24);
	u8 b2 = (u8)(word >> 16);
	u8 b3 = (u8)(word >> 8);
	u8 b4 = (u8)word;
	u8 *word_arr = malloc(sizeof(u8) * 4);
	word_arr[0] = b1;
	word_arr[1] = b2;
	word_arr[2] = b3;
	word_arr[3] = b4;

	return word_arr;
}


static u32 rot_word(u32 word) {
	u8 b1 = (u8)(word >> 24);

	u32 temp = word << 8;
	temp = temp | (u32)b1;

	return temp;
}

static u32 sub_word(u32 word) {
	u8 *word_arr = bytes_from_word(word);

	u8 sub_word[4] = { 0 };
	for (u32 i = 0; i < 4; i++) {
		sub_word[i] = sbox(word_arr[i]);
	}

	free(word_arr);

	return word_from_bytes(sub_word[0], sub_word[1], sub_word[2], sub_word[3]);
}

static u32 rcon(u32 i) {
	u8 rcon_lookup[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
	u8 rconB[4] = {rcon_lookup[i-1], 0x00, 0x00, 0x00};
	return word_from_bytes(rconB[0], rconB[1], rconB[2], rconB[3]);
}

static u32 *key_expansion(char *key, u32 nr, u32 nk) {
	u32 temp;
	u32 i = 0;
	u32 *w = malloc(sizeof(u32) * NB * (nr + 1));

	while (i < nk) {
		w[i] = word_from_bytes(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
		i++;
	}

	i = nk;

	while (i < NB * (nr + 1)) {
		temp = w[i-1];
		if ((i % nk) == 0) {
			temp = sub_word(rot_word(temp)) ^ rcon(i/nk);
		}
		else if ((nk > 6) && ((i % nk) == 4)) {
			temp = sub_word(temp);
		}

		w[i] = w[i-nk] ^ temp;
		i++;
	}
	
	return w;
}

static void add_round_key(u8 *state, u32 *w, u32 round) {

	u32 l = round * NB;

	// Iterate over columns of state and xor each one with w[l+c]
	for (u32 c = 0; c < NB; c++) {
		u32 state_word = word_from_bytes(state[0*NB+c], state[1*NB+c],
										 state[2*NB+c], state[3*NB+c]);

		state_word = state_word ^ w[l+c];

		u8 *state_bytes = bytes_from_word(state_word);
		
		state[0 * NB + c] = state_bytes[0];
		state[1 * NB + c] = state_bytes[1];
		state[2 * NB + c] = state_bytes[2];
		state[3 * NB + c] = state_bytes[3];

		free(state_bytes);
	}
}

static void sub_bytes(u8 *state) {
	for (u32 c = 0; c < NB; c++) {
		for (u32 r = 0; r < ROWS; r++) {
			state[r * NB + c] = sbox(state[r * NB + c]);
		}
	}
}

static void shift_rows(u8 *state) {
	// ROW 1 = 1 left
	u8 r1c0 = state[1*NB+0];
	state[1*NB+0] = state[1*NB+1];
	state[1*NB+1] = state[1*NB+2];
	state[1*NB+2] = state[1*NB+3];
	state[1*NB+3] = r1c0;

	// ROW 2 = 2 left
	u8 r2c0 = state[2*NB+0];
	u8 r2c1 = state[2*NB+1];
	state[2*NB+0] = state[2*NB+2];
	state[2*NB+1] = state[2*NB+3];
	state[2*NB+2] = r2c0;
	state[2*NB+3] = r2c1;

	// ROW 3 = 1 right = 3 left
	u8 r3c3 = state[3*NB+3];
	state[3*NB+3] = state[3*NB+2];
	state[3*NB+2] = state[3*NB+1];
	state[3*NB+1] = state[3*NB+0];
	state[3*NB+0] = r3c3;
}

static u8 xtime(u8 x) {
	if (x & 0x80)
		return ((x << 1) ^ 0x1b) & 0xff;
	return x << 1;
}

static void mix_columns(u8 *state) {
	for (u32 c = 0; c < NB; c++) {

		u8 all_xor = state[0*NB+c] ^ state[1*NB+c] ^
			state[2*NB+c] ^ state[3*NB+c];

		u8 r_0 = state[0*NB+c];

		state[0*NB+c] ^= xtime(state[0*NB+c] ^ state[1*NB+c]) ^ all_xor;

		state[1*NB+c] ^= xtime(state[1*NB+c] ^ state[2*NB+c]) ^ all_xor;

		state[2*NB+c] ^= xtime(state[2*NB+c] ^ state[3*NB+c]) ^ all_xor;

		state[3*NB+c] ^= xtime(state[3*NB+c] ^ r_0) ^ all_xor;
	}
}

static char *bytes_from_state(u8 *state) {
	// 128 / 8 = 16 bytes (1 block)
	char *out = malloc(sizeof(char) * (BLOCK / BYTE) + 1);
	for (u32 c = 0; c < NB; c++) {
		for (u32 r = 0; r < ROWS; r++) {
			out[r + (4 * c)] = state[r * NB + c];
		}
	}
	return out;
}




static void inv_shift_rows(u8 *state) {
	// ROW 1 = 1 right
	u8 r1c3 = state[1*NB+3];
	state[1*NB+3] = state[1*NB+2];
	state[1*NB+2] = state[1*NB+1];
	state[1*NB+1] = state[1*NB+0];
	state[1*NB+0] = r1c3;

	// ROW 2 = 2 right
	u8 r2c2 = state[2*NB+2];
	u8 r2c3 = state[2*NB+3];
	state[2*NB+3] = state[2*NB+1];
	state[2*NB+2] = state[2*NB+0];
	state[2*NB+1] = r2c3;
	state[2*NB+0] = r2c2;

	// ROW 3 = 1 left = 3 right
	u8 r3c0 = state[3*NB+0];
	state[3*NB+0] = state[3*NB+1];
	state[3*NB+1] = state[3*NB+2];
	state[3*NB+2] = state[3*NB+3];
	state[3*NB+3] = r3c0;
}

static void inv_sub_bytes(u8 *state) {
	for (u32 c = 0; c < NB; c++) {
		for (u32 r = 0; r < ROWS; r++) {
			state[r * NB + c] = inv_sbox(state[r * NB + c]);
		}
	}
}

static void inv_mix_columns(u8 *state) {
	for (u32 c = 0; c < NB; c++) {
		u8 s0c = state[0*NB+c];
		u8 s1c = state[1*NB+c];
		u8 s2c = state[2*NB+c];
		u8 s3c = state[3*NB+c];

		u8 s0c_hex02 = xtime(s0c);
		u8 s0c_hex04 = xtime(s0c_hex02);
		u8 s0c_hex08 = xtime(s0c_hex04);

		u8 s1c_hex02 = xtime(s1c);
		u8 s1c_hex04 = xtime(s1c_hex02);
		u8 s1c_hex08 = xtime(s1c_hex04);

		u8 s2c_hex02 = xtime(s2c);
		u8 s2c_hex04 = xtime(s2c_hex02);
		u8 s2c_hex08 = xtime(s2c_hex04);

		u8 s3c_hex02 = xtime(s3c);
		u8 s3c_hex04 = xtime(s3c_hex02);
		u8 s3c_hex08 = xtime(s3c_hex04);

		// Calculating state row 0, col c
		state[0*NB+c] =
			(s0c_hex02 ^ s0c_hex04 ^ s0c_hex08) ^
			(s1c ^ s1c_hex02 ^ s1c_hex08) ^
			(s2c ^ s2c_hex04 ^ s2c_hex08) ^
			(s3c ^ s3c_hex08);

		// Calculating state row 1, col c
		state[1*NB+c] =
			(s0c ^ s0c_hex08) ^
			(s1c_hex02 ^ s1c_hex04 ^ s1c_hex08) ^
			(s2c ^ s2c_hex02 ^ s2c_hex08) ^
			(s3c ^ s3c_hex04 ^ s3c_hex08);

		// Calculating state row 2, col c
		state[2*NB+c] =
			(s0c ^ s0c_hex04 ^ s0c_hex08) ^
			(s1c ^ s1c_hex08) ^
			(s2c_hex02 ^ s2c_hex04 ^ s2c_hex08) ^
			(s3c ^ s3c_hex02 ^ s3c_hex08);

		// Calculating state row 3, col c
		state[3*NB+c] =
			(s0c ^ s0c_hex02 ^ s0c_hex08) ^
			(s1c ^ s1c_hex04 ^ s1c_hex08) ^
			(s2c ^ s2c_hex08) ^
			(s3c_hex02 ^ s3c_hex04 ^ s3c_hex08);
	}
}




/* PUBLIC FUNCTIONS */
char *aes_encrypt_block(char *data, char *key, u32 key_size) {

	u8 *state = state_from_bytes(data);

	u32 nr = 0;
	u32 nk = 0;
	u32 key_bit_length = key_size * 8;
	switch (key_bit_length) {
	case 128:
		nr = 10;
		nk = 4;
		break;
	case 192:
		nr = 12;
		nk = 6;
		break;
	case 256:
		nr = 14;
		nk = 8;
		break;
	default:
		printf("Invalid Key size\n");
		exit(1);
		break;
	}

	u32 *key_schedule = key_expansion(key, nr, nk);

	u32 round = 0;
	add_round_key(state, key_schedule, round);

	// Rounds 1 to nr-1
	for (round = 1; round < nr; round++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, key_schedule, round);
	}

	// Round nr
	sub_bytes(state);
	shift_rows(state);
	round = nr;
	add_round_key(state, key_schedule, round);

	char *output = bytes_from_state(state);

	free(state);
	free(key_schedule);

	return output;
}


char *aes_decrypt_block(char *cipher, char *key, u32 key_size) {

	u8 *state = state_from_bytes(cipher);
	
	u32 nr = 0;
	u32 nk = 0;
	u32 key_bit_length = key_size * 8;
	switch (key_bit_length) {
	case 128:
		nr = 10;
		nk = 4;
		break;
	case 192:
		nr = 12;
		nk = 6;
		break;
	case 256:
		nr = 14;
		nk = 8;
		break;
	default:
		printf("Invalid Key size\n");
		exit(1);
		break;
	}

	u32 *key_schedule = key_expansion(key, nr, nk);

	u32 round = nr;
	add_round_key(state, key_schedule, round);

	// Rounds nr-1 to 1
	for (round = nr-1; round > 0; round--) {
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, key_schedule, round);
		inv_mix_columns(state);
	}

	// Round 0
	inv_shift_rows(state);
	inv_sub_bytes(state);
	round = 0;
	add_round_key(state, key_schedule, round);
	
	char *output = bytes_from_state(state);

	free(state);
	free(key_schedule);

	return output;
}


/* ========== TESTS ========== */
void aes_test_enc() {
	char plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};


	// 128 bit key tests
	char key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	const char expected_128[16 + 1] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, '\0'};
	// Encrypt and assert
	char *cipher_128 = aes_encrypt_block(plaintext, key_128, sizeof(key_128));
	cipher_128[16] = '\0';
	assert(strcmp(cipher_128, expected_128) == 0);
	free(cipher_128);


	// 192 bit key tests
	char key_192[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
	const char expected_192[16+1] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91, '\0'};
	// Encrypt and assert
	char *cipher_192 = aes_encrypt_block(plaintext, key_192, sizeof(key_192));
	cipher_192[16] = '\0';
	assert(strcmp(cipher_192, expected_192) == 0);
	free(cipher_192);


	// 256 bit key tests
	char key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	const char expected_256[16+1] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89, '\0'};
	// Encrypt and assert
	char *cipher_256 = aes_encrypt_block(plaintext, key_256, sizeof(key_256));
	cipher_256[16] = '\0';
	assert(strcmp(cipher_256, expected_256) == 0);
	free(cipher_256);


	return;
}


void aes_test_dec() {
	char expected[16+1] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, '\0'};


	// 128 bit key tests
	char cipher_128[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	char key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	// Decrypt and assert
	char *plain_128 = aes_decrypt_block(cipher_128, key_128, sizeof(key_128));
	plain_128[16] = '\0';
	assert(strcmp(plain_128, expected) == 0);
	free(plain_128);


	// 192 bit key tests
	char cipher_192[16] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};
	char key_192[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
	// Decrypt and assert
	char *plain_192 = aes_decrypt_block(cipher_192, key_192, sizeof(key_192));
	plain_192[16] = '\0';
	assert(strcmp(plain_192, expected) == 0);
	free(plain_192);


	// 256 bit key tests
	char cipher_256[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
	char key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	// Decrypt and assert
	char *plain_256 = aes_decrypt_block(cipher_256, key_256, sizeof(key_256));
	plain_256[16] = '\0';
	assert(strcmp(plain_256, expected) == 0);
	free(plain_256);


	return;
}
