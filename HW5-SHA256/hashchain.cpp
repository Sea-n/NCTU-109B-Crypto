#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <iostream>
#include <fstream>

/*
 * SHA256 Hash
 *
 * Introduction to Cryptography  Homework #5
 *
 * Source Code: https://git.io/SHA
 *
 * 2021-05-23 by Sean, 0816146 韋詠祥
 */

using namespace std;
using namespace CryptoPP;

string toHex(string str, size_t size = 0);

int main() {
	string digest, digestHex;
	string msg, prev, nonce;
	ofstream out;
	SHA256 hash;
	int nonceInt;
	int Z, z;

	out.open("out.txt", ios_base::app);
	out << "Problem 2:\n";
	digest.resize(32);
	nonce.resize(4);

	msg = "Bitcoin";
	hash.Update((const byte*) msg.data(), msg.size());
	hash.Final((byte*) &digest[0]);

	for (Z=0; Z<7; Z++) {
		nonceInt = 0;
		prev = digest;

		do {
			nonce[0] = (char) ((nonceInt >> 24) & 0xFF);
			nonce[1] = (char) ((nonceInt >> 16) & 0xFF);
			nonce[2] = (char) ((nonceInt >>  8) & 0xFF);
			nonce[3] = (char) ((nonceInt >>  0) & 0xFF);

			msg = prev + nonce;
			hash.Update((const byte*) msg.data(), 36);
			hash.Final((byte*) &digest[0]);
			digestHex = toHex(digest);

			for (z=0; digestHex.c_str()[z] == '0'; z++) ;
		} while (Z > z && ++nonceInt);

		out << Z << '\n' << toHex(prev) << '\n';
		out << toHex(nonce) << '\n' << toHex(digest) << "\n\n";
	}

	return 0;
}

string toHex(string str, size_t size) {
	if (size == 0) size = str.size();
	string hex;
	StringSource ss((const byte*) str.c_str(), size, true,
			new HexEncoder(new StringSink(hex)));

	return hex;
}
