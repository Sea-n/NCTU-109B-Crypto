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
	const byte key[17] = "1234567890ABCDEF";
	const byte iv0[17] = "0000000000000000";
	const byte iv9[17] = "9999999999999999";

	const string plaintext = "AES is the block cipher standard.";
	string cfbCip, cb0Cip, cb9Cip, ecbCip;
	string cfbRec, cb0Rec, cb9Rec, ecbRec;

	const AlgorithmParameters cfbP = MakeParameters
		(Name::FeedbackSize(), 4)
		(Name::IV(), ConstByteArrayParameter(iv0, 16));

	/* Encryption */
	CFB_Mode<AES>::Encryption cfbEnc; cfbEnc.SetKey(key, 16, cfbP);
	CBC_Mode<AES>::Encryption cb0Enc(key, 16, iv0);
	CBC_Mode<AES>::Encryption cb9Enc(key, 16, iv9);
	ECB_Mode<AES>::Encryption ecbEnc(key, 16);


	StreamTransformationFilter cfbStfE(cfbEnc, new StringSink(cfbCip), StreamTransformationFilter::NO_PADDING);
	StreamTransformationFilter cb0StfE(cb0Enc, new StringSink(cb0Cip), StreamTransformationFilter::ZEROS_PADDING);
	StreamTransformationFilter cb9StfE(cb9Enc, new StringSink(cb9Cip), StreamTransformationFilter::PKCS_PADDING);
	StreamTransformationFilter ecbStfE(ecbEnc, new StringSink(ecbCip), StreamTransformationFilter::PKCS_PADDING);

	cfbStfE.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	cb0StfE.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	cb9StfE.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	ecbStfE.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());

	cfbStfE.MessageEnd();
	cb0StfE.MessageEnd();
	cb9StfE.MessageEnd();
	ecbStfE.MessageEnd();

	/* Write answer to file */
	FILE *fd = fopen("out.txt", "w");

	for (const byte c : cfbCip) fprintf(fd, "%02x ", c & 0xFF); fputs("\n", fd);
	for (const byte c : cb0Cip) fprintf(fd, "%02x ", c & 0xFF); fputs("\n", fd);
	for (const byte c : cb9Cip) fprintf(fd, "%02x ", c & 0xFF); fputs("\n", fd);
	for (const byte c : ecbCip) fprintf(fd, "%02x ", c & 0xFF); fputs("\n", fd);

	fclose(fd);

	/* Decryption */
	CFB_Mode<AES>::Decryption cfbDec; cfbDec.SetKey(key, 16, cfbP);
	CBC_Mode<AES>::Decryption cb0Dec(key, 16, iv0);
	CBC_Mode<AES>::Decryption cb9Dec(key, 16, iv9);
	ECB_Mode<AES>::Decryption ecbDec(key, 16);

	StreamTransformationFilter cfbStfD(cfbDec, new StringSink(cfbRec), StreamTransformationFilter::NO_PADDING);
	StreamTransformationFilter cb0StfD(cb0Dec, new StringSink(cb0Rec), StreamTransformationFilter::ZEROS_PADDING);
	StreamTransformationFilter cb9StfD(cb9Dec, new StringSink(cb9Rec), StreamTransformationFilter::PKCS_PADDING);
	StreamTransformationFilter ecbStfD(ecbDec, new StringSink(ecbRec), StreamTransformationFilter::PKCS_PADDING);

	cfbStfD.Put(reinterpret_cast<const unsigned char*>(cfbCip.c_str()), cfbCip.length());
	cb0StfD.Put(reinterpret_cast<const unsigned char*>(cb0Cip.c_str()), cb0Cip.length());
	cb9StfD.Put(reinterpret_cast<const unsigned char*>(cb9Cip.c_str()), cb9Cip.length());
	ecbStfD.Put(reinterpret_cast<const unsigned char*>(ecbCip.c_str()), ecbCip.length());

	cfbStfD.MessageEnd();
	cb0StfD.MessageEnd();
	cb9StfD.MessageEnd();
	ecbStfD.MessageEnd();

	/* Check if it matches original plaintext manually */
	cout << "Decrypted Text (CFB Mode): " << cfbRec << '\n';
	cout << "Decrypted Text (CBC Mode): " << cb0Rec << '\n';
	cout << "Decrypted Text (CBC Mode): " << cb9Rec << '\n';
	cout << "Decrypted Text (ECB Mode): " << ecbRec << '\n';

	return 0;
}
