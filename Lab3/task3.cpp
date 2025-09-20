// pch.cpp: source file corresponding to the pre-compiled header

// Linux help: http://www.cryptopp.com/wiki/Linux


#include <iostream>
using namespace std;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;
#include "cryptopp/integer.h"
using CryptoPP::Integer;
#include "cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;
#include<cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;
#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
#include "cryptopp/sha.h"
using CryptoPP::SHA1;
#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;




// Declare functions with extern "C" to prevent name mangling in C++ 




//save file, key binary
void Save(const string& filename, const BufferedTransformation& bt);
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

// key 64 
void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);
void SaveBase64(const string& filename, const BufferedTransformation& bt);


void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);



void GenerateAndSaveRSAKeys(int KeySize, const char* format, const char* privateKeyFile, const char* publicKeyFile) {

	string strFormat(format);
	string strPrivateKeyFile(privateKeyFile);
	string strPublicKeyFile(publicKeyFile);
	AutoSeededRandomPool rnd;
	RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rnd, KeySize);
	RSA::PublicKey rsaPublic(rsaPrivate);
	// Save keys
	if (strFormat == "DER")
	{
		SavePrivateKey(strPrivateKeyFile, rsaPrivate);
		SavePublicKey(strPublicKeyFile, rsaPublic);


	}
	else if (strFormat == "PEM")
	{
		SaveBase64PrivateKey(strPrivateKeyFile, rsaPrivate);
		SaveBase64PublicKey(strPublicKeyFile, rsaPublic);
	} else {
		cout << "Please choose BER or PEM" << endl;
		exit(1);
	}
	cout << "Successfully generated and saved RSA keys" << endl;
}

void RSAencryptFromInput(const char* format, const char * plaintext, const char* publicKeyFile, const char *savefile)
{
    RSA::PublicKey publicKey;
    string strFormat(format);
    string strPublicKeyFile(publicKeyFile);

    if (strFormat == "DER") {
        LoadPublicKey(strPublicKeyFile, publicKey);
    }
    else if (strFormat == "PEM") {
        LoadBase64PublicKey(strPublicKeyFile, publicKey);
    }
    else {
        cout << "Please choose DER or PEM" << endl;
        exit(1);
    }

    // Nhập plaintext từ người dùng
    string plain = plaintext;
    AutoSeededRandomPool rnd;
    //Encryption
    RSAES_OAEP_SHA_Encryptor e(publicKey);
	string cipher;
	string save(savefile);
	if(save != "0")
	{
		if (strFormat == "DER") {
			StringSource(plain, true, new PK_EncryptorFilter(rnd, e, new FileSink(savefile, true)));
		} else if (strFormat == "PEM")
		{
			StringSource(plain, true, new PK_EncryptorFilter(rnd, e, new StringSink(cipher)));
			StringSource(cipher, true, new Base64Encoder(new FileSink(savefile), false));
		}
	} else {
    StringSource(plain, true, new PK_EncryptorFilter(rnd, e, new StringSink(cipher)));
	if (strFormat == "DER") {
        cout << "Ciphertext (DER format): " << cipher << endl;
    } 
    else if (strFormat == "PEM") {
        string encoded;
        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), false));
        cout << "Ciphertext (PEM format): " << encoded  << endl;
    }
	}
}
void RSAdecryptFromInput(const char* format, const char* ciphertext, const char * privateKeyFile, const char* saveFile)
{
    RSA::PrivateKey privateKey;
	string strFormat(format);
	string strSecretKeyFile(privateKeyFile);
	if (strFormat == "DER")
	{

		LoadPrivateKey(privateKeyFile, privateKey);

	}
	else if (strFormat == "PEM")
		LoadBase64PrivateKey(privateKeyFile, privateKey);
	else {
		cout << "Please choose DER or PEM" << endl;
		exit(1);
	}
	string cipher = ciphertext;
	if (strFormat == "PEM") {
        // Decode Base64 if PEM
        string decodedCipher;
        StringSource(cipher, true, new Base64Decoder(new StringSink(decodedCipher)));
        cipher = decodedCipher;
    }

	AutoSeededRandomPool rnd;
	//Decrypt
	RSAES_OAEP_SHA_Decryptor d(privateKey);
	string decrypt;
	string save(saveFile);
	if(save =="0")
	{
    	StringSource(cipher, true, new PK_DecryptorFilter(rnd, d, new StringSink(decrypt)));
		cout << "Decrypted: " << decrypt << endl;
	} else 
	{
		
		StringSource(cipher, true, new PK_DecryptorFilter(rnd, d, new FileSink(saveFile, true)));
		cout << "File saved" << endl;

	}
}
void RSAencryptFromFile(const char* format, const char* PLaintextFile, const char* publicKeyFile, const char* CipherFile)
{
	RSA::PublicKey publicKey;
	string strFormat(format);
	string strPublicKeyFile(publicKeyFile);
	if (strFormat == "DER")
	{
		LoadPublicKey(strPublicKeyFile, publicKey);
	}
	else if (strFormat == "PEM")
	{
		LoadBase64PublicKey(strPublicKeyFile, publicKey);
	}
	else

	{
		cout << "Please choose DER or PEM" << endl;
		exit(1);
	}
	string plain;
	AutoSeededRandomPool rnd;
	FileSource(PLaintextFile, true, new StringSink(plain), false);
	string save(CipherFile);
	//Encryption
	string cipher;
	RSAES_OAEP_SHA_Encryptor e(publicKey);
	if(save == "0")
	{ 
		StringSource(plain, true, new PK_EncryptorFilter(rnd, e, new StringSink(cipher)));
	if (strFormat == "DER") {
        cout << "Ciphertext (DER format): " << cipher << endl;
    } 
    else if (strFormat == "PEM") {
        string encoded;
        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), false));
        cout << "Ciphertext (PEM format): " << encoded  << endl;
    }
	} else {
	if (strFormat == "DER") {
			StringSource(plain, true, new PK_EncryptorFilter(rnd, e, new FileSink(CipherFile, true)));
		} else if (strFormat == "PEM")
		{
			StringSource(plain, true, new PK_EncryptorFilter(rnd, e, new StringSink(cipher)));
			StringSource(cipher, true, new Base64Encoder(new FileSink(CipherFile), false));
		}
	cout << "Encrypted message saved to file" << endl;
	}
}

void RSADecryptFromFile(const char* format, const char* CipherFile,const char* secretKeyFile,  const char* PlaintextFile)
{
	RSA::PrivateKey privateKey;
	string strFormat(format);
	string strSecretKeyFile(secretKeyFile);
	if (strFormat == "DER")
	{

		LoadPrivateKey(secretKeyFile, privateKey);


	}
	else if (strFormat == "PEM")
		LoadBase64PrivateKey(secretKeyFile, privateKey);
	else {
		cout << "Please choose DER or PEM" << endl;
		exit(1);
	}
	string cipher;
	AutoSeededRandomPool rnd;
	if (strFormat == "PEM") {
        // Decode Base64 if PEM
        FileSource file(CipherFile, true, new Base64Decoder(new StringSink(cipher)));
    } else {
	FileSource(CipherFile, true, new StringSink(cipher), true);
	}
	//Decrypt
	RSAES_OAEP_SHA_Decryptor d(privateKey);
	//StringSource(cipher, true, new PK_DecryptorFilter(rnd, d, new FileSink(PlaintextFile, true)));
	string decrypt;
	string save(PlaintextFile);
	
	if(save =="0")
	{
    	StringSource(cipher, true, new PK_DecryptorFilter(rnd, d, new StringSink(decrypt)));
		cout << "Decrypted: " << decrypt << endl;
	} else 
	{
		StringSource(cipher, true, new PK_DecryptorFilter(rnd, d, new FileSink(PlaintextFile, true)));
		cout << "File saved" << endl;
	}
}

int main(int argc, char** argv)
{
	
	std::ios_base::sync_with_stdio(false);
//void RSAencryptFromInput(const char* format, const char* privateKeyFile, const char * plaintext, const char* publicKeyFile, const char* CipherFile)
	if (argc < 2) {
		std::cerr << "Usage: \n"
			<< argv[0] << " genkey: <keysize> <format> <privateKeyFile> <publicKeyFile>" << std::endl
			<< argv[0] << " encrypt:<inputtype> <format> <plaintext/plaintextfile> <publickeyfile>  <Cipherfile>" << std::endl
			<< argv[0] << " decrypt:<inputtype> <format> <ciphertext/Cipherfile> <privatekeyfile>  <PlainFile> " << std::endl;
		return -1;
	}
	clock_t start, end;
    double duration;
    double total = 0;
	string mode = argv[1];
	string input = argv[2];
	for(int i = 0; i < 10000; i++)
	{
	start = clock();
	if (mode == "genkey") {
		int keySize = std::stoi(argv[2]);
		GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
	}
	else if(mode == "encrypt" && input == "input")  {
		RSAencryptFromInput(argv[3], argv[4], argv[5], argv[6]);

	}
	else if (mode == "encrypt" && input == "file")
	{
		//void RSAencrypt(const char* format, const char* privateKeyFile, const char* PLaintextFile, const char* publicKeyFile, const char* CipherFile)
		RSAencryptFromFile(argv[3], argv[4], argv[5], argv[6]);

	} else if (mode == "decrypt" && input == "input")
	{
		RSAdecryptFromInput(argv[3], argv[4], argv[5], argv[6]);
	}
	
	else if (mode == "decrypt" && input == "file")
	{
		//void RSADecrypt(const char* format, const char* secretKeyFile, const char* CipherFile, const char* publicKeyFile, const char* PlaintextFile)

		RSADecryptFromFile(argv[3], argv[4], argv[5], argv[6]);
	}
	end = clock();
    duration = ((double)(end - start)) / CLOCKS_PER_SEC;
    std::cout << "Execute time: " << duration << std::endl;
    total += duration;
	}
	cout << "total:" << total << endl;
	return 0;
}

//def fy

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	// Create a FileSource that automatically decodes Base64 data from the file
	CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);

	// Load the decoded data into a ByteQueue
	CryptoPP::ByteQueue queue;
	file.TransferTo(queue);
	queue.MessageEnd();

	// Load the private key from the ByteQueue
	key.Load(queue);

	// Optionally, check the validity of the loaded key
	CryptoPP::AutoSeededRandomPool prng;
	if (!key.Validate(prng, 3)) {
		throw std::runtime_error("Loaded private key is invalid.");
	}
}
void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	// Create a FileSource that automatically decodes Base64 data from the file
	CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);

	// Load the decoded data into a ByteQueue
	CryptoPP::ByteQueue queue;
	file.TransferTo(queue);
	queue.MessageEnd();

	// Load the public key from the ByteQueue
	key.Load(queue);
	// Optionally, check the validity of the loaded key
	AutoSeededRandomPool prng;
	if (!key.Validate(prng, 3)) {
		throw std::runtime_error("Loaded public key is invalid.");
	}
}


void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}

