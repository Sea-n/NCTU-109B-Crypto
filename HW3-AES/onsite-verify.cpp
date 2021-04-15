#include <iostream>
#include <iomanip>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>

/*
 * AES Encryption
 *
 * Introduction to Cryptography  Homework #3
 *
 * Source Code: https://git.io/AES
 *
 * 2021-04-04 by Sean, 0816146 韋詠祥
 */

using namespace std;
using namespace CryptoPP;

int main() {
	const byte key[17] = "AES Key:81243716";
	const byte iv0[17] = "0000000000000000";

	const string ans1 = "RSA is a public-key system.";
	const string ans2 = "Pseudorandom numbers";
	const string ans3 = "The Advanced Encryption Standard";
	string ecbCip, cbcCip, cfbCip;
	string ecbRec, cbcRec, cfbRec;

	const AlgorithmParameters cfbP = MakeParameters
		(Name::FeedbackSize(), 2)
		(Name::IV(), ConstByteArrayParameter(iv0, 16));

	/* Encryption */
	ECB_Mode<AES>::Encryption ecbEnc(key, 16);
	CBC_Mode<AES>::Encryption cbcEnc(key, 16, iv0);
	CFB_Mode<AES>::Encryption cfbEnc; cfbEnc.SetKey(key, 16, cfbP);


	StreamTransformationFilter ecbStfE(ecbEnc, new StringSink(ecbCip), StreamTransformationFilter::ZEROS_PADDING);
	StreamTransformationFilter cbcStfE(cbcEnc, new StringSink(cbcCip), StreamTransformationFilter::PKCS_PADDING);
	StreamTransformationFilter cfbStfE(cfbEnc, new StringSink(cfbCip), StreamTransformationFilter::ZEROS_PADDING);

	ecbStfE.Put(reinterpret_cast<const unsigned char*>(ans1.c_str()), ans1.length());
	cbcStfE.Put(reinterpret_cast<const unsigned char*>(ans2.c_str()), ans2.length());
	cfbStfE.Put(reinterpret_cast<const unsigned char*>(ans3.c_str()), ans3.length());

	ecbStfE.MessageEnd();
	cbcStfE.MessageEnd();
	cfbStfE.MessageEnd();

	for (const byte c : ecbCip) { printf("%02x ", c & 0xFF); }  puts("");
	for (const byte c : cbcCip) { printf("%02x ", c & 0xFF); }  puts("");
	for (const byte c : cfbCip) { printf("%02x ", c & 0xFF); }  puts("");

	/* Decryption */
	ECB_Mode<AES>::Decryption ecbDec(key, 16);
	CBC_Mode<AES>::Decryption cbcDec(key, 16, iv0);
	CFB_Mode<AES>::Decryption cfbDec; cfbDec.SetKey(key, 16, cfbP);

	StreamTransformationFilter ecbStfD(ecbDec, new StringSink(ecbRec), StreamTransformationFilter::ZEROS_PADDING);
	StreamTransformationFilter cbcStfD(cbcDec, new StringSink(cbcRec), StreamTransformationFilter::PKCS_PADDING);
	StreamTransformationFilter cfbStfD(cfbDec, new StringSink(cfbRec), StreamTransformationFilter::ZEROS_PADDING);

	ecbStfD.Put(reinterpret_cast<const unsigned char*>(ecbCip.c_str()), ecbCip.length());
	cbcStfD.Put(reinterpret_cast<const unsigned char*>(cbcCip.c_str()), cbcCip.length());
	cfbStfD.Put(reinterpret_cast<const unsigned char*>(cfbCip.c_str()), cfbCip.length());

	ecbStfD.MessageEnd();
	cbcStfD.MessageEnd();
	cfbStfD.MessageEnd();

	/* Check if it matches original plaintext manually */
	cout << "Decrypted Text (ECB Mode): " << ecbRec << '\n';
	cout << "Decrypted Text (CBC Mode): " << cbcRec << '\n';
	cout << "Decrypted Text (CFB Mode): " << cfbRec << '\n';

	return 0;
}
