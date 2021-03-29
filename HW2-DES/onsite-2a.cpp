#include <iostream>
#include <fstream>
#include <cstring>

#define CIPHER_ONLY true

/*
 * DES Encryption
 *
 * Introduction to Cryptography  Homework #2
 *
 * Source Code: https://git.io/DES
 *
 * 2021-03-22 by Sean, 0816146 韋詠祥
 */

using namespace std;

string encDES(const string keyStr, const string txtStr);
const bool *F(const bool R[32], const bool key[48]);
const bool *xor_bin(const bool *A, const bool *B, const int len);

int main() {
	clock_t begin, end;
	double cpu_time_used;
	string line, key, txt, enc;

	begin = clock();

	key = "12345678";
	txt = "security";

	enc = encDES(key, txt);

	cout << key << ' ' << txt << ' ' << enc << '\n';

	end = clock();

	cpu_time_used = ((double) (end - begin)) / CLOCKS_PER_SEC * 1000;
	cout << "CPU Time used: " << cpu_time_used << " ms\n";

	return 0;	
}


/*
 * ========== BEGIN OF CONSTANTS ==========
 */

static const char hex_digits[17] = "0123456789ABCDEF";

static const int table_ip[64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

static const int table_fp[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

static const int table_pc1[56] = {
	57, 49, 41, 33, 25, 17, 9,
	1,  58, 50, 42, 34, 26, 18,
	10, 2,  59, 51, 43, 35, 27,
	19, 11, 3,  60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7,  62, 54, 46, 38, 30, 22,
	14, 6,  61, 53, 45, 37, 29,
	21, 13, 5,  28, 20, 12, 4
};

static const int table_pc2[48] = {
	14, 17, 11, 24, 1,  5,
	3,  28, 15, 6,  21, 10,
	23, 19, 12, 4,  26, 8,
	16, 7,  27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

static const int table_e[48] = {
	32, 1,  2,  3,  4,  5,
	4,  5,  6,  7,  8,  9,
	8,  9,  10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

static const int table_p[32] = {
	16, 7,  20, 21, 29, 12, 28, 17,
	1,  15, 23, 26, 5,  18, 31, 10,
	2,  8,  24, 14, 32, 27, 3,  9,
	19, 13, 30, 6,  22, 11, 4,  25
};

static const int table_s[8][64] = {
	{ // S1
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
	},
	{ // S7
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
	},
	{ // S3
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
	},
	{ // S4
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
	},
	{ // S5
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
	},
	{ // S6
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
	},
	{ // S2
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
	},
	{ // S8
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
	}
};


/*
 * ========== BEGIN OF FUNCTIONS ==========
 */

string encDES(const string keyStr, const string txtStr) {
	bool keyBin[64], txtBin[64], tmpBin[64];
	bool subBin[48], CiDi[56];

	/* String to Binary */
	for (int i=0, k=0; i<8; i++)
		for (int j=128; j>0; j>>=1) {
			keyBin[k] = (keyStr[i] & j) ? 1 : 0;
			txtBin[k] = (txtStr[i] & j) ? 1 : 0;
			k++;
		}

	/* Initial Permutation */
	for (int i=0; i<64; i++)
		tmpBin[i] = txtBin[table_ip[i]-1];
	memcpy(txtBin, tmpBin, 64);


	/* Permuted Choice 1 */
	for (int i=0; i<56; i++)
		CiDi[i] = keyBin[table_pc1[i]-1];

	/* Encryption Rounds */
	for (int round=0; round<16; round++) {
		/* Left circular shift */
		int flag = !(round == 1 || round == 2 || round == 8 || round == 10);

		do {
			tmpBin[0] = CiDi[0],  tmpBin[1] = CiDi[28];
			for (int i=0; i<55; i++)
				CiDi[i] = CiDi[i+1];
			CiDi[27] = tmpBin[0], CiDi[55] = tmpBin[1];
		} while (flag--);

		/* Permuted Choice 2 */
		for (int i=0; i<48; i++)
			subBin[i] = CiDi[table_pc2[i]-1];

		/* Round iterate */
		bool oldL[32], oldR[32];
		memcpy(oldL, txtBin, 32);
		memcpy(oldR, &txtBin[32], 32);
		const bool *fstl = F(oldR, subBin);
		const bool *newR = xor_bin(oldL, fstl, 32);
		memcpy(txtBin, oldR, 32);
		memcpy(&txtBin[32], newR, 32);
	}

	/* 32-bit Swap */
	memcpy(tmpBin, txtBin, 32);
	memcpy(txtBin, &txtBin[32], 32);
	memcpy(&txtBin[32], tmpBin, 32);

	/* Final Permutation */
	for (int i=0; i<64; i++)
		tmpBin[i] = txtBin[table_fp[i]-1];
	memcpy(txtBin, tmpBin, 64);

	/* Convert binary to hex */
	string encStr;
	for (int i=0; i<64; i+=4)
		encStr += hex_digits[ txtBin[i+0]<<3 | txtBin[i+1]<<2 | txtBin[i+2]<<1 | txtBin[i+3] ];
	return encStr;
}

/* Feistel */
const bool *F(const bool R[32], const bool key[48]) {
	/* Expansion */
	bool *resE = new bool[48];
	for (int i=0; i<48; i++)
		resE[i] = R[table_e[i]-1];

	/* Exclusive-OR */
	const bool *resX = xor_bin(resE, key, 48);

	/* Substitution */
	bool *resS = new bool[32];
	for (int i=0, j=0, k=0; i<48; i+=6) {
		int idx = resX[i]<<5 | resX[i+5]<<4 | resX[i+1]<<3 | resX[i+2]<<2 | resX[i+3]<<1 | resX[i+4];
		int val = table_s[j++][idx];
		for (int x=8; x>0; x>>=1)
			resS[k++] = (val & x) ? 1 : 0;
	}

	/* Permutation */
	bool *resP = new bool[32];
	for (int i=0; i<32; i++)
		resP[i] = resS[table_p[i]-1];

	return resP;
}

/* XOR for binary array */
const bool *xor_bin(const bool *A, const bool *B, const int len) {
	bool *C = new bool[len];
	for (int i=0; i<len; i++)
		C[i] = A[i] ^ B[i];
	return C;
}
