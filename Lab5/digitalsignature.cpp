#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h> // Include for SHA256
#include <iostream>
#include <fstream>
#include <vector> // Include for std::vector
#include <iterator> // Include for std::istreambuf_iterator
#include<string>
using namespace std;
#ifndef DLL_EXPORT 

    #ifdef _WIN32 

        #define DLL_EXPORT __declspec(dllexport) 

    #else 

        #define DLL_EXPORT 

#endif 

#endif 
using namespace std;
extern "C" {
    DLL_EXPORT void generateAndSaveRSAPSSKey(const char * format, const char *prvkeyFile, const char *pubkeyFile); //RSASS key gen
    DLL_EXPORT void generateandsaveECCKey(const char *format, const char *prvkeyFile, const char * pubkeyFile); // ECDSA key gen
    DLL_EXPORT const char* LoadMessage(const char *MessageFile); // Load Mess
    DLL_EXPORT bool signMessageRSAPSS(const char* chrPrivateKeyPath, const char* message, const char* chrSignaturePath); //Sign using RSASS
    DLL_EXPORT bool verifyMessageSignatureRSASS(const char* chrPublicKeyPath, const char* message, const char* chrSignaturePath); //verify RSASS
    DLL_EXPORT bool signMessage(const char* chrPrivateKeyPath, const char* message, const char* chrSignaturePath); // sign using ECDSA
    DLL_EXPORT bool verifyMessageSignature(const char* chrPublicKeyPath, const char * message, const char* chrSignaturePath); //verify using ECDSA
}
const char* LoadMessage(const char *MessageFile)
{
    string messagefile(MessageFile);
    string message;
    fstream file;
    file.open(messagefile, ios_base::in);
    file >> message;
    file.close();
    return message.c_str();
}
void generateAndSaveRSAPSSKey(const char * format, const char *prvkeyFile, const char *pubkeyFile) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
    
    if (!pctx) {
        std::cerr << "Error creating PKEY context" << std::endl;
        exit(1);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        std::cerr << "Error initializing keygen" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    // Set the RSA key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        std::cerr << "Error setting RSA key size" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        std::cerr << "Error generating RSA key" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    EVP_PKEY_CTX_free(pctx);

    // Save the private key
    BIO *bioprv = BIO_new_file(prvkeyFile, "w");
    if (!bioprv) {
        std::cerr << "Unable to open file " << prvkeyFile << std::endl;
        EVP_PKEY_free(pkey);
        exit(1);
    }
        if (strcmp(format, "PEM") == 0) {
        if (!PEM_write_bio_PrivateKey(bioprv, pkey, NULL, NULL, 0, NULL, NULL)) {
            std::cerr << "Error writing private key in PEM format." << std::endl;
        }
    } else if (strcmp(format, "DER") == 0) {
        if (!i2d_PrivateKey_bio(bioprv, pkey)) {
            std::cerr << "Error writing private key in BER format." << std::endl;
        }
    } else {
        std::cerr << "Unsupported format: " << format << std::endl;
    }
    BIO_free(bioprv);
    BIO *biopub = BIO_new_file(pubkeyFile, "w");
    if (!biopub) {
        std::cerr << "Unable to open file " << pubkeyFile << std::endl;
        EVP_PKEY_free(pkey);
        return;
    }
    if (strcmp(format, "PEM") == 0) {
        if (!PEM_write_bio_PUBKEY(biopub, pkey)) {
            std::cerr << "Error writing public key in PEM format." << std::endl;
        }
    } else if (strcmp(format, "DER") == 0) {
        
        if (!i2d_PUBKEY_bio(biopub, pkey)) {
            std::cerr << "Error writing public key in BER format." << std::endl;
        }
    } else {
        std::cerr << "Unsupported format: " << format << std::endl;
    }
    BIO_free(biopub);
    EVP_PKEY_free(pkey);
    std::cout << "Key generated!" << std::endl;
}

void generateandsaveECCKey(const char *format, const char *prvkeyFile, const char * pubkeyFile) {
    int eccgrp;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (!pctx) {
        std::cerr << "Error creating context for key generation." << std::endl;
        return;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        std::cerr << "Error initializing key generation context." << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        std::cerr << "Error setting EC curve." << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        std::cerr << "Error generating key." << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY_CTX_free(pctx);

    BIO *bioprv = BIO_new_file(prvkeyFile, "w");
    if (!bioprv) {
        std::cerr << "Unable to open file " << prvkeyFile << std::endl;
        EVP_PKEY_free(pkey);
        return;
    }

    if (strcmp(format, "PEM") == 0) {
        if (!PEM_write_bio_PrivateKey(bioprv, pkey, NULL, NULL, 0, NULL, NULL)) {
            std::cerr << "Error writing private key in PEM format." << std::endl;
        }
    } else if (strcmp(format, "DER") == 0) {
        if (!i2d_PrivateKey_bio(bioprv, pkey)) {
            std::cerr << "Error writing private key in BER format." << std::endl;
        }
    } else {
        std::cerr << "Unsupported format: " << format << std::endl;
    }
    BIO_free(bioprv);
    BIO *biopub = BIO_new_file(pubkeyFile, "w");
    if (!biopub) {
        std::cerr << "Unable to open file " << pubkeyFile << std::endl;
        EVP_PKEY_free(pkey);
        return;
    }
    if (strcmp(format, "PEM") == 0) {
        if (!PEM_write_bio_PUBKEY(biopub, pkey)) {
            std::cerr << "Error writing public key in PEM format." << std::endl;
        }
    } else if (strcmp(format, "DER") == 0) {
        
        if (!i2d_PUBKEY_bio(biopub, pkey)) {
            std::cerr << "Error writing public key in BER format." << std::endl;
        }
    } else {
        std::cerr << "Unsupported format: " << format << std::endl;
    }
    BIO_free(biopub);
    EVP_PKEY_free(pkey);

    std::cout << "Key generated!" << std::endl;
}

bool signMessageRSAPSS(const char* chrPrivateKeyPath, const char* message, const char* chrSignaturePath) {
    std::string privateKeyPath(chrPrivateKeyPath), signaturePath(chrSignaturePath), messagepath(message);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read the private key from file
    BIO *keyData = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyData, privateKeyPath.c_str()) <= 0) {
        std::cerr << "Error reading private key file." << std::endl;
        BIO_free(keyData);
        ERR_free_strings();
        return false;
    }

    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(keyData, NULL, NULL, NULL);
    BIO_free(keyData);
    if (!privateKey) {
        std::cerr << "Error reading private key." << std::endl;
        ERR_print_errors_fp(stderr);
        ERR_free_strings();
        return false;
    }

    // Hash the message
    unsigned char hash[SHA512_DIGEST_LENGTH];
    if (!SHA512(reinterpret_cast<const unsigned char*>(messagepath.c_str()), messagepath.length(), hash)) {
        std::cerr << "Error hashing the message." << std::endl;
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Create the signature context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx) {
        std::cerr << "Error creating signature context." << std::endl;
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        std::cerr << "Error initializing signature context." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Set the padding type to PSS
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        std::cerr << "Error setting PSS padding." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Set the hash function for the PSS padding
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) <= 0) {
        std::cerr << "Error setting signature hash." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Determine buffer length for the signature
    size_t siglen;
    if (EVP_PKEY_sign(ctx, NULL, &siglen, hash, SHA512_DIGEST_LENGTH) <= 0) {
        std::cerr << "Error determining buffer length for signature." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Allocate buffer for the signature
    std::vector<unsigned char> signature(siglen);

    // Create the signature
    if (EVP_PKEY_sign(ctx, signature.data(), &siglen, hash, SHA512_DIGEST_LENGTH) <= 0) {
        std::cerr << "Error creating signature." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Write the signature to a file
    std::ofstream signatureFile(signaturePath, std::ios::binary);
    if (!signatureFile.is_open()) {
        std::cerr << "Error opening signature file." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }
    signatureFile.write(reinterpret_cast<const char*>(signature.data()), siglen);
    signatureFile.close();

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();
    
    std::cout << "done";
    return true;
}

bool signMessage(const char* chrPrivateKeyPath, const char* message, const char* chrSignaturePath) {
    std::string privateKeyPath(chrPrivateKeyPath), signaturePath(chrSignaturePath), messagepath(message);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read the private key from file
    BIO *keyData = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyData, privateKeyPath.c_str()) <= 0) {
        std::cerr << "Error reading private key file." << std::endl;
        BIO_free(keyData);
        ERR_free_strings();
        return false;
    }

    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(keyData, NULL, NULL, NULL);
    BIO_free(keyData);
    if (!privateKey) {
        std::cerr << "Error reading private key." << std::endl;
        ERR_print_errors_fp(stderr);
        ERR_free_strings();
        return false;
    }

    // Create a buffer to hold the message hash
    unsigned char hash[SHA512_DIGEST_LENGTH];
    
    // Hash the message
    std::cout << "Hashing the message" << std::endl;
    if (!SHA512(reinterpret_cast<const unsigned char*>(messagepath.c_str()), messagepath.length(), hash)) {
        std::cerr << "Error hashing the message." << std::endl;
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Sign the hash
    std::cout << "Signing the hash" << std::endl;
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_SignInit(mdCtx, EVP_sha512());
    EVP_SignUpdate(mdCtx, hash, SHA512_DIGEST_LENGTH);

    // Allocate buffer for the signature
    unsigned int signatureLen = EVP_PKEY_size(privateKey);
    std::vector<unsigned char> signature(signatureLen);

    if (!EVP_SignFinal(mdCtx, signature.data(), &signatureLen, privateKey)) {
        std::cerr << "Error signing message." << std::endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }

    // Write the signature to a file
    std::cout << "Writing the signature to file: " << signaturePath << std::endl;
    std::ofstream signatureFile(signaturePath, std::ios::binary);
    if (!signatureFile.is_open()) {
        std::cerr << "Error opening signature file." << std::endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        ERR_free_strings();
        return false;
    }
    signatureFile.write(reinterpret_cast<const char*>(signature.data()), signatureLen);
    signatureFile.close();

    // Clean up
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();
    std::cout << "done";
    return true;
}
bool verifyMessageSignatureRSASS(const char* chrPublicKeyPath, const char* message, const char* chrSignaturePath) {
    std::string publicKeyPath(chrPublicKeyPath), signaturePath(chrSignaturePath), messagePath(message);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Load the public key (PEM) using BIO
    BIO *pubData = BIO_new(BIO_s_file());
    if (BIO_read_filename(pubData, publicKeyPath.c_str()) <= 0) {
        std::cerr << "Error opening public key file." << std::endl;
        BIO_free(pubData);
        ERR_free_strings();
        return false;
    }
    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(pubData, NULL, NULL, NULL);
    BIO_free(pubData);

    if (!publicKey) {
        std::cerr << "Error loading public key." << std::endl;
        ERR_print_errors_fp(stderr);
        ERR_free_strings();
        return false;
    }

    // Hash the message
    unsigned char hash[SHA512_DIGEST_LENGTH];
    if (!SHA512(reinterpret_cast<const unsigned char*>(messagePath.c_str()), messagePath.length(), hash)) {
        std::cerr << "Error hashing the message." << std::endl;
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }

    // Load the signature
    std::ifstream signatureFile(signaturePath, std::ios::binary);
    if (!signatureFile.is_open()) {
        std::cerr << "Error opening signature file." << std::endl;
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }
    std::vector<unsigned char> signature(std::istreambuf_iterator<char>(signatureFile), {});
    signatureFile.close();

    // Create the verification context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx) {
        std::cerr << "Error creating verification context." << std::endl;
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        std::cerr << "Error initializing verification context." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }

    // Set the padding type to PSS
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        std::cerr << "Error setting PSS padding." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }

    // Set the hash function for the PSS padding
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) <= 0) {
        std::cerr << "Error setting signature hash." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }

    // Verify the signature
    int result = EVP_PKEY_verify(ctx, signature.data(), signature.size(), hash, SHA512_DIGEST_LENGTH);
    if (result == 1) {
        std::cout << "Message verified successfully" << std::endl;
    } else {
        std::cout << "Failed to verify the message" << std::endl;
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();
    ERR_free_strings();

    return result;
}

bool verifyMessageSignature(const char* chrPublicKeyPath, const char * message, const char* chrSignaturePath) {
    std::string publicKeyPath(chrPublicKeyPath), signaturePath(chrSignaturePath), messagePath(message);
    bool k;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Load the public key (PEM) using BIO
    BIO *pubData = BIO_new(BIO_s_file());
    if (BIO_read_filename(pubData, publicKeyPath.c_str()) <= 0) {
        std::cerr << "Error opening public key file." << std::endl;
        BIO_free(pubData);
        ERR_free_strings();
        return false;
    }
    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(pubData, NULL, NULL, NULL);
    BIO_free(pubData);

    if (!publicKey) {
        std::cerr << "Error loading public key." << std::endl;
        ERR_print_errors_fp(stderr);
        ERR_free_strings();
        return false ;
    }

    // Create a buffer to hold the message hash
    unsigned char hash[SHA512_DIGEST_LENGTH];
    
    // Hash the message
    std::cout << "Hashing the message" << std::endl;
    if (!SHA512(reinterpret_cast<const unsigned char*>(messagePath.c_str()), messagePath.length(), hash)) {
        std::cerr << "Error hashing the message." << std::endl;
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }

    // Load the signature
    std::ifstream signatureFile(signaturePath, std::ios::binary);
    if (!signatureFile.is_open()) {
        std::cerr << "Error opening signature file." << std::endl;
        EVP_PKEY_free(publicKey);
        ERR_free_strings();
        return false;
    }
    std::vector<unsigned char> signature(std::istreambuf_iterator<char>(signatureFile), {});
    signatureFile.close();

    // Verify the signature
    std::cout << "Verifying the signature" << std::endl;
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha512(), NULL, publicKey);
    EVP_DigestVerifyUpdate(mdCtx, hash, SHA512_DIGEST_LENGTH);
    int result = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());
    if(result == 1) {
        std::cout << "Message verified successfully" << std::endl;
    } else {
        std::cout << "Failed to verify the message" << std::endl;
    }
    // Clean up
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();
    ERR_free_strings();
    return result;
}

int main(int argc, char* argv[]) {
    // Initialize OpenSSL
    clock_t start, end;

    if (argc < 3 )
    {
        std::cerr << "Usage: " << argv[0] << "[algo] [sign|verify|genkey]  <other options>" << std::endl;
        return 1;
    }
    std::string algo(argv[1]);
    std::string mode(argv[2]);
    double total = 0;
    for(int i = 0; i <1000; i++) {
    start=clock();
    if(mode == "genkey" && algo == "ECDSA")
    {
        generateandsaveECCKey(argv[3], argv[4], argv[5]);
    } else if(mode == "genkey" && algo == "RSASS-PSS")
    {
        generateAndSaveRSAPSSKey(argv[3], argv[4], argv[5]);
    }
    std::string inputmode(argv[3]);
    if((mode == "sign" && algo == "ECDSA") && inputmode == "file")
    {
        if(argc != 7)
        {
            std::cerr << "Usage: " << argv[0] << " sign: <input mode> <private key file> <file: .txt> <signature file>" << std::endl;
            return 1;
        }
    const char * m = LoadMessage(argv[5]);
    if (!signMessage(argv[4], m, argv[6])) {
        std::cout << "Failed to sign Message." << std::endl;
    }
    }else if ((mode == "sign" && algo == "RSASS-PSS") && inputmode == "file") {
        if(argc != 7)
        {
            std::cerr << "Usage: " << argv[0] << " sign: <input mode> <private key file> <file: .txt> <signature file>" << std::endl;
            return 1;
        }
        const char * m = LoadMessage(argv[5]);
    if (!signMessageRSAPSS(argv[4], m, argv[6])) {
        
        std::cout << "Failed to sign Message." << std::endl;
    }
    } else if (mode == "sign" && algo == "ECDSA" && inputmode == "input") {
        if(argc != 7)
        {
            std::cerr << "Usage: " << argv[0] << " sign: <input mode> <private key file> <message> <signature file>" << std::endl;
            return 1;
        }
    if (!signMessage( argv[4], argv[5], argv[6])) {
        
        std::cout << "Failed to sign Message." << std::endl;
    }
    } else if (mode == "sign" && algo == "RSASS-PSS" && inputmode == "input")
    {
         if(argc != 7)
        {
            std::cerr << "Usage: " << argv[0] << " sign: <input mode> <private key file> <file: .txt> <signature file>" << std::endl;
            return 1;
        }
        if (!signMessageRSAPSS(argv[4], argv[5], argv[6])) {
        
         std::cout << "Failed to sign Message." << std::endl;
         }
    }
     else if (mode == "verify" && algo == "ECDSA" && inputmode == "file")
    {
        if (argc != 7) {
        std::cerr << "Usage: " << argv[0] << " verify: <input mode> <public key file> <file: .txt> <signature file>" << std::endl;
        return 1;
        }
        const char * m = LoadMessage(argv[5]);
        if (!verifyMessageSignature(argv[4], m, argv[6])) {
        std::cout << "Failed to verify Message." << std::endl;
     }
    } else if(mode == "verify" && algo == "RSASS-PSS" && inputmode == "file")
    {
        if (argc != 7) {
        std::cerr << "Usage: " << argv[0] << " verify: <input mode> <public key file> <file: .txt> <signature file>" << std::endl;
        return 1;
        }
        const char * m = LoadMessage(argv[5]);
        if (!verifyMessageSignatureRSASS(argv[4], m, argv[6])) {
        std::cout << "Failed to verify Message." << std::endl;
     }
    }
    else if  (mode == "verify" && algo== "ECDSA" && inputmode == "input")
    {
        if(argc != 7)
        {
            std::cerr << "Usage: " << argv[0] << " verify:<input mode> <public key file> <message> <signature file>" << std::endl;
            return 1;
        }
     if (!verifyMessageSignature(argv[4], argv[5], argv[6])) {
        std::cout << "Failed to verify Message." << std::endl;
     }
    } else if (mode == "verify" && algo== "RSASS-PSS" && inputmode == "input")
    {
         if(argc != 7)
        {
            std::cerr << "Usage: " << argv[0] << " verify:<input mode> <public key file> <message> <signature file>" << std::endl;
            return 1;
        }
     if (!verifyMessageSignatureRSASS(argv[4], argv[5], argv[6])) {
        std::cout << "Failed to verify Message." << std::endl;
     }
    }
    end = clock();
    double duration;
    duration = ((double)(end - start)) / CLOCKS_PER_SEC;
    total += duration;
    }
    cout << "total:" << total << endl;
}


