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

int main() {
	string msg, digest, digestHex;
	ofstream out;
	SHA256 hash;

	out.open("out.txt");
	msg = "Bitcoin is a cryptocurrency, a form of electronic cash.";

	hash.Update((const byte*) msg.data(), msg.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte*) &digest[0]);

	StringSource ss((const byte*) digest.c_str(), digest.size(), true,
			new HexEncoder(new StringSink(digestHex)));

	out << "Problem 1:\n" << digestHex << "\n\n";

	return 0;
}

