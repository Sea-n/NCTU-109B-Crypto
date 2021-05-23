#include <cryptopp/filters.h>
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

const string toHex(const string str);

int main() {
	string digestHex, digest(32, 0);
	string msg, prev, nonce(4, 0);
	int nonceInt, Z, z;
	ofstream out;
	SHA256 hash;

	out.open("out.txt", ios_base::app);
	out << "Problem 2:\n";

	msg = "Bitcoin";
	hash.Update((const byte*) msg.data(), msg.size());
	hash.Final((byte*) &digest[0]);

	for (Z=0; Z<8; Z++) {
		nonceInt = 0;
		prev = digest;

		do {
			nonce[0] = (const char) ((nonceInt >> 24) & 0xFF);
			nonce[1] = (const char) ((nonceInt >> 16) & 0xFF);
			nonce[2] = (const char) ((nonceInt >>  8) & 0xFF);
			nonce[3] = (const char) ((nonceInt >>  0) & 0xFF);

			msg = prev + nonce;
			hash.Update((const byte*) msg.data(), 36);
			hash.Final((byte*) &digest[0]);
			digestHex = toHex(digest);

			for (z=0; digestHex.c_str()[z] == '0'; z++) ;
		} while (Z > z && ++nonceInt);

		out << Z << '\n' << toHex(prev) << '\n';
		out << toHex(nonce) << '\n' << digestHex << endl;
	}

	return 0;
}

const string toHex(const string str) {
	string hex;
	StringSource ss((const byte*) str.c_str(), str.size(), true,
			new HexEncoder(new StringSink(hex)));

	return hex;
}
