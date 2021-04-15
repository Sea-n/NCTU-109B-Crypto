#include <iostream>
#include <iomanip>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>

/*
 * AES Encryption
 *
 * Introduction to Cryptography  Homework #3 On-site
 *
 * Source Code: https://git.io/AES
 *
 * 2021-04-15 by Sean, 0816146 韋詠祥
 */

using namespace std;
using namespace CryptoPP;

int main() {
	const byte key[17] = "AES Key:81243716";

	const unsigned char ciphers[3][65] = {
		"\x3e\xb0\x14\xeb\x02\x7a\x97\xdd\x37\xd6\x2e\x76\xe9\xaa\x93\xaa\x5f\xd2\x02\x18\xfd\x2f\x5a\x2e\x3a\x6a\xb3\x0f\x82\x66\x95\x72",
		"\xb2\xba\x8d\x9b\xef\x06\xd9\xde\x06\xaf\x55\x36\x29\x6d\x36\x10\x72\x09\x5a\x04\xe4\xd4\xee\xfa\xb3\xc9\xf9\xd3\x00\x28\x27\x8a",
		"\xf5\xa3\x3a\xf0\x9e\xba\x92\x48\x60\x79\x7f\x44\xea\xf6\xad\xa1\x8c\x72\x79\x4a\xd2\x06\x0a\x82\x23\x12\x76\xc0\x4d\x90\xd3\x16"
	};

	const byte ivs[2][17] = {
		"0000000000000000",
		"9999999999999999"
	};

	const BlockPaddingSchemeDef::BlockPaddingScheme paddings[2] = {
		StreamTransformationFilter::ZEROS_PADDING,
		StreamTransformationFilter::PKCS_PADDING
	};

	/* Decryption */
	for (const unsigned char* cipher : ciphers) {
		printf("# Ciphertext: %02x %02x\n", cipher[0], cipher[1]);
		for (const byte* iv : ivs) {
			printf("## IV: %s\n", iv);
			for (const BlockPaddingSchemeDef::BlockPaddingScheme &padding : paddings) {
				printf("### padding: %d\n", padding);

				string cf2Rec, cf4Rec, cbcRec, ecbRec;

				const AlgorithmParameters cf2P = MakeParameters
					(Name::FeedbackSize(), 2)
					(Name::IV(), ConstByteArrayParameter(iv, 16));

				const AlgorithmParameters cf4P = MakeParameters
					(Name::FeedbackSize(), 4)
					(Name::IV(), ConstByteArrayParameter(iv, 16));

				CFB_Mode<AES>::Decryption cf2Dec; cf2Dec.SetKey(key, 16, cf2P);
				CFB_Mode<AES>::Decryption cf4Dec; cf4Dec.SetKey(key, 16, cf4P);
				CBC_Mode<AES>::Decryption cbcDec(key, 16, iv);
				ECB_Mode<AES>::Decryption ecbDec(key, 16);

				StreamTransformationFilter cf2StfD(cf2Dec, new StringSink(cf2Rec), StreamTransformationFilter::ZEROS_PADDING);
				StreamTransformationFilter cf4StfD(cf4Dec, new StringSink(cf4Rec), StreamTransformationFilter::ZEROS_PADDING);
				StreamTransformationFilter cbcStfD(cbcDec, new StringSink(cbcRec), padding);
				StreamTransformationFilter ecbStfD(ecbDec, new StringSink(ecbRec), padding);

				cf2StfD.Put(reinterpret_cast<const unsigned char*>(cipher), 32);
				cf4StfD.Put(reinterpret_cast<const unsigned char*>(cipher), 32);
				cbcStfD.Put(reinterpret_cast<const unsigned char*>(cipher), 32);
				ecbStfD.Put(reinterpret_cast<const unsigned char*>(cipher), 32);

				try { cf2StfD.MessageEnd(); } catch (...) {}
				try { cf4StfD.MessageEnd(); } catch (...) {}
				try { cbcStfD.MessageEnd(); } catch (...) {}
				try { ecbStfD.MessageEnd(); } catch (...) {}

				/* Check if it matches original plaintext manually */
				if (padding == StreamTransformationFilter::ZEROS_PADDING) {
					cout << "Decrypted Text (CFB Mode): '" << cf2Rec << "'\n";
					cout << "Decrypted Text (CFB Mode): '" << cf4Rec << "'\n";
				}
				cout << "Decrypted Text (CBC Mode): '" << cbcRec << "'\n";
				if (iv == ivs[0]) {
					cout << "Decrypted Text (ECB Mode): '" << ecbRec << "'\n";
				}

				puts("");
			}
			puts("");
		}
		puts("");
	}

	return 0;
}
