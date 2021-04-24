#include <iostream>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

/*
 * RSA Encryption
 *
 * Introduction to Cryptography  Homework #4
 *
 * Source Code: https://git.io/RSA
 *
 * 2021-04-24 by Sean, 0816146 韋詠祥
 */

using namespace std;
using namespace CryptoPP;

const Integer enc(const long e, const string nStr, const string mStr);
const string dec(const long e, const Integer n, const Integer d, const Integer c);
const pair<const string, const int> dec(const string dStr, const string nStr, const string cStr);

int main() {
	ofstream out;
	out.open("out.txt");

	{
		const Integer c = enc(0x11, "0xb14022eef719f1bb", "Alice");
		cout << "1. cipher=" << hex << c << '\n';
	}

	{
		const Integer c = enc(0x11, "0xb2c8d1404ed5fc2f7ad1254bb428f0d5", "Hello World!");
		out << "Ciphertext 1 = " << hex << c << '\n';
	}

	{
		const Integer c = enc(0x10001, "0xcf625a8e47bc1cf9a3b517b31d870108c0cd97466003842a3b394d6cd857e9b7", "RSA is public key.");
		out << "Ciphertext 2 = " << hex << c << '\n';
	}

	{
		auto p = dec("0x16282b21a7866bf5", "0x9d001e6473dfacf9", "0x154c638cd3615216");
		string m = p.first; int e = p.second;
		assert(m != "" && "Decryption failed");

		cout << "2. msg=" << m << ", e=0x" << hex << e << '\n';
	}

	{
		auto p = dec("0x12e6a85100b889c9905a939b274a91bc57ca85d52e6c464fb455c86a29d63c89",
				"0xd6361e40b2d619970ead338912a273adb75a4ce21356304834753fe94e6de24b",
				"0xa1676afd68a2fc67dac32c633600b76fa90aca9f9cca5201490a20c8b01a061a");
		string m = p.first; int e = p.second;
		assert(m != "" && "Decryption failed");

		out << "Message = " << m << "\nPublic key = 0x" << hex << e << '\n';
	}

	return 0;
}

const Integer enc(const long e, const string nStr, const string mStr) {
	const Integer n(nStr.c_str());
	const Integer m((const byte *) mStr.data(), mStr.size());

	RSA::PublicKey pubKey;
	pubKey.Initialize(n, e);

	const Integer c = pubKey.ApplyFunction(m);

	return c;
}

const string dec(const long e, const Integer d, const Integer n, const Integer c) {
	AutoSeededRandomPool prng;
	string msg;

	RSA::PrivateKey priKey;
	try {
		priKey.Initialize(n, e, d);
	} catch (InvalidArgument e) {
		return "";
	}

	const Integer r = priKey.CalculateInverse(prng, c);
	msg.resize(r.MinEncodedSize());
	r.Encode((byte *) msg.data(), msg.size());

	return msg;
}

const pair<const string, const int> dec(const string dStr, const string nStr, const string cStr) {
	const Integer d(dStr.c_str());
	const Integer n(nStr.c_str());
	const Integer c(cStr.c_str());

	for (int e=3; e<1<<30; e+=e-1) {
		const string m = dec(e, d, n, c);
		if (m != "") return {m, e};
	}

	return {"", 0};
}
