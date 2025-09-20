
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
#include <string>
using std::string;
#include <cstdlib>
using std::exit;
#include<ctime>
// CryptoPP

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
#include "cryptopp/base64.h" // làm việc với base64
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::ArraySink;
#include "cryptopp/aes.h"
using CryptoPP::AES;

using namespace std;
#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/secblock.h"
#include <cstddef>
using CryptoPP::SecByteBlock;
void GenerateKeyAndIv(const char* KeyFile, const char * IvFile)
{
    AutoSeededRandomPool prng;

	CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	CryptoPP::byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
    string Key;
    string Iv;
    StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(Key)
		) // HexEncoder
	); 
    StringSource(Key, true, new FileSink(KeyFile));
    cout << "Key generated:" << Key << std::endl;
    StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(Iv)
		) // HexEncoder
	); 
    StringSource(Iv, true, new FileSink(IvFile));

    cout << "Iv generated: " << Iv << std::endl;
}

void EncryptFromFile(int mode, const char* plainFile, const char* ivFile, const char* keyFile, const char *cipherFile)
{
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];    
	CryptoPP::byte iv[AES::BLOCKSIZE];
    string plain, IV, Key;
    FileSource (ivFile, true, new StringSink(IV));
    FileSource(keyFile, true, new StringSink(Key));    
    FileSource ivSource(ivFile, new ArraySink(iv, sizeof(iv)));
    FileSource keySource(keyFile, true, new ArraySink(key, sizeof(key)));
    FileSource plainSource(plainFile, true, new StringSink(plain));    
    string cipher, encoded, recovered;
    cout << "key: "  << Key << endl;
    cout << "iv: "  << IV << endl;
    cout << "plain text: " << plain << endl;
     switch (mode)
        {
            case 1:
            {
                CBC_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));
                break;
            }
            case 2:
            {
                ECB_Mode< AES >::Encryption e; 
                e.SetKey(key, sizeof(key));
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));
                break;
            }
            case 3:
            {
                OFB_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;

            }
            case 4:
            {
                CFB_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 5:
            {
                CTR_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 6:
            {
                GCM < AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 7:
            {
                CCM < AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 8:
            {
                XTS < AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }


        };
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );
    cout << "cipher text (hex): " << encoded << endl;
    StringSource(encoded, true, new FileSink(cipherFile));


}

void DecryptFromFile(int mode, const char* cipherFile, const char* ivFile, const char* keyFile, const char *plainFile)
{
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];    
    CryptoPP::byte iv[AES::BLOCKSIZE];
    string ciphertextF, IV, Key;
    
    // Read IV and Key from files
    FileSource(ivFile, true, new ArraySink(iv, sizeof(iv)));
    FileSource(keyFile, true, new ArraySink(key, sizeof(key)));
    
    // Read ciphertext from file
    FileSource(cipherFile, true, new StringSink(ciphertextF));
    
    string ciphertext, recovered;
    
    // Decode the hex-encoded ciphertext
    StringSource(ciphertextF, true,
        new HexDecoder(
            new StringSink(ciphertext)
        )
    );

    switch (mode)
    {
        case 1: // CBC Mode
        {
            CBC_Mode<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(e,
                    new StringSink(recovered),
                    StreamTransformationFilter::PKCS_PADDING
                )
            );
            break;
        }
        case 2: // ECB Mode
        {
            ECB_Mode<AES>::Decryption e; 
            e.SetKey(key, sizeof(key));
            StringSource(ciphertext, true,
                new StreamTransformationFilter(e,
                    new StringSink(recovered),
                    StreamTransformationFilter::PKCS_PADDING
                )
            );
            break;
        }
        case 3: // OFB Mode
        {
            OFB_Mode<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(e,
                    new StringSink(recovered)
                )
            );        
            break;
        }
        case 4: // CFB Mode
        {
            CFB_Mode<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(e,
                    new StringSink(recovered)
                )
            );        
            break;
        }
        case 5: // CTR Mode
        {
            CTR_Mode<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(e,
                    new StringSink(recovered)
                )
            );        
            break;
        }
        case 6: // GCM Mode
        {
            GCM<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new AuthenticatedDecryptionFilter(e,
                    new StringSink(recovered)
                )
            );        
            break;
        }
        case 7: // CCM Mode
        {
            CCM<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new AuthenticatedDecryptionFilter(e,
                    new StringSink(recovered)
                )
            );        
            break;
        }
        case 8: // XTS Mode
        {
            XTS<AES>::Decryption e; 
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(e,
                    new StringSink(recovered)
                )
            );        
            break;
        }
        default:
            throw invalid_argument("Invalid mode");
    }
    
    cout << "recovered text: " << recovered << endl;
    StringSource(recovered, true, new FileSink(plainFile));
}
/*void DecryptFromFile(int mode, const char* cipherFile, const char* ivFile, const char* keyFile, const char *plainFile)
{
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];    
	CryptoPP::byte iv[AES::BLOCKSIZE];
    string ciphertextF, IV, Key;
    FileSource (ivFile, true, new StringSink(IV));
    FileSource(keyFile, true, new StringSink(Key));    
    FileSource ivSource(ivFile, true, new ArraySink(iv, sizeof(iv)));
    FileSource keySource(keyFile, true, new ArraySink(key, sizeof(key)));
    FileSource cipherSource(cipherFile, true, new StringSink(ciphertextF));    
    string encoded;
    cout << "key: "  << Key << endl;
    cout << "iv: "  << IV << endl;
    cout << "ciphertext: " << ciphertextF << endl;
    string ciphertext, recovered;
    StringSource(ciphertextF, true,
        new HexEncoder(
            new StringSink(ciphertext)
        )
    );
    switch (mode)
    {
        case 1:
            {
                CBC_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));
                break;
            }
            case 2:
            {
                ECB_Mode< AES >::Decryption e; 
                e.SetKey(key, sizeof(key));
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));
                break;
            }
            case 3:
            {
                OFB_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;

            }
            case 4:
            {
                CFB_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 5:
            {
                CTR_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 6:
            {
                GCM < AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 7:
            {
                CCM < AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 8:
            {
                XTS < AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
    }
    cout << "recovered text: " << recovered << endl;
    StringSource(recovered, true, new FileSink(plainFile));

    
} */
string EncryptFromInput(int mode, const char* plaintext, const char* iv_hex, const char* key_hex) {
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];    
	CryptoPP::byte iv[AES::BLOCKSIZE];
    AutoSeededRandomPool prng;
    StringSource(key_hex, true, new ArraySink(key, sizeof(key)));
    StringSource(iv_hex, true, new ArraySink(iv, sizeof(iv)));
    string cipher, encoded, recovered;
    cout << "key: " << key_hex << endl;
    cout << "iv: " << iv_hex << endl;
    cout << "plain text: " << plaintext << endl;
    
      switch (mode)
        {
            case 1:
            {
                CBC_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));
                break;
            }
            case 2:
            {
                ECB_Mode< AES >::Encryption e; 
                e.SetKey(key, sizeof(key));
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));
                break;
            }
            case 3:
            {
                OFB_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;

            }
            case 4:
            {
                CFB_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 5:
            {
                CTR_Mode< AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 6:
            {
                GCM < AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 7:
            {
                CCM < AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }
            case 8:
            {
                XTS < AES >::Encryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(plaintext, true,new StreamTransformationFilter(e,new StringSink(cipher)));        
                break;
            }


        };
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );
    cout << "cipher text (hex): " << encoded << endl;
    return encoded;
}
string DecryptFromInput(int mode, const char* ciphertexthex, const char* iv_hex, const char* key_hex)
{
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];    
	CryptoPP::byte iv[AES::BLOCKSIZE];

    StringSource(key_hex, true, new ArraySink(key, sizeof(key)));
    StringSource(iv_hex, true, new ArraySink(iv, sizeof(iv)));

    string recovered;
    cout << "key: " << key_hex << endl;
    cout << "iv: " << iv_hex << endl;
    cout << "Ciphertext: " << ciphertexthex << endl;
    string ciphertext;
    StringSource(ciphertexthex, true,
        new HexDecoder(
            new StringSink(ciphertext)
        )
    );
    switch (mode)
    {
          case 1:
            {
                CBC_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));
                break;
            }
            case 2:
            {
                ECB_Mode< AES >::Decryption e; 
                e.SetKey(key, sizeof(key));
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));
                break;
            }
            case 3:
            {
                OFB_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;

            }
            case 4:
            {
                CFB_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 5:
            {
                CTR_Mode< AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 6:
            {
                GCM < AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 7:
            {
                CCM < AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
            case 8:
            {
                XTS < AES >::Decryption e; 
                e.SetKeyWithIV(key, sizeof(key), iv);
                StringSource(ciphertext, true,new StreamTransformationFilter(e,new StringSink(recovered)));        
                break;
            }
    }

    cout << "recovered text: " << recovered << endl;
    return recovered;
}
int main(int argc, char* argv[])
{
    clock_t start, end;
    double duration;
    std::ios_base::sync_with_stdio(false);
    if (argc < 1) {
    cerr << "Usage: \n"
         << argv[0] << "<genkey>: <KeyFile> <IVFile>" << endl
         << argv[0] << "<encrypt>:<I/O type> <mode> <plaintext> <IV> <Key> " << endl
         << argv[0] << "<decrypt>: <I/O type> <mode> <cipher> <IV> <Key>" << endl;
    }
    //    cerr << "Your input type: " << argv[0] << " <keyboard> <file> " << endl;
    //EncryptFromInput(2, "Buổi thực hành 1 - phạm mạnh kha", "77E68E1651FFA8E4", " 4A9AD2DE2C7DC25F");
    //DecryptFromInput(1, "66D5BAF723F6F47F3D12AB38530B8C9CDAD25CD4286867FB2E4267DC2019443CE58FF62A1B9E82D2AE6B0EB3FA9FCAD8", "77E68E1651FFA8E4", "4A9AD2DE2C7DC25F"); 
    //GenerateKeyAndIv("RdGeneratedKey", "RdGeneratedIv");
    string options = argv[1];
            start = clock();
    if(options == "genkey" )
    {
        GenerateKeyAndIv(argv[2], argv[3]);
    } else if (options == "encrypt")
    {
        string type = argv[2];
        int m = std::stoi(argv[3]);
        if(type == "input")
        {
            EncryptFromInput(m, argv[4] , argv[5], argv[6]);
        } else if (type == "file")
        {
            EncryptFromFile(m, argv[4], argv[5], argv[6], argv[7]);
        } 
    } else if (options == "decrypt")
    {
        string type = argv[2];
        int m = std::stoi(argv[3]);
        if(type == "input")
        {
            DecryptFromInput(m, argv[4] , argv[5], argv[6]);
        } else if (type == "file")
        {
            DecryptFromFile(m, argv[4], argv[5], argv[6], argv[7]);
        } 
    }
    end = clock();
    duration = ((double)(end - start)) / CLOCKS_PER_SEC;
    std::cout << "Execute time: " << duration << std::endl;
    return 0;
}





