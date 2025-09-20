#include <openssl/sha.h>
#include <iostream>
#include<vector>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/evp.h>
#include <fstream>
#include<string>
#include <cstring>

using namespace std;
#ifndef DLL_EXPORT 

    #ifdef _WIN32 

        #define DLL_EXPORT __declspec(dllexport) 

    #else 

        #define DLL_EXPORT 

#endif 

#endif 
extern "C" {
    DLL_EXPORT const char* sha224(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* sha256(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* sha384(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* sha512(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* SHA3_224(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* SHA3_256(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* SHA3_384(const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* SHA3_512 (const char *Input , const char *Inputfile  ,const char* Outputfile );
    DLL_EXPORT const char* shake128(const char *Input , const char *Inputfile  ,const char* Outputfile, const char * Digestlength);
    DLL_EXPORT const char* shake256(const char *Input , const char *Inputfile  ,const char* Outputfile, const char * Digestlength);
}
const char* sha224(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    // Tạo một ngữ cảnh băm
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-224
    const EVP_MD* md = EVP_sha224();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-224
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
            cout << "Hashed: " << ss.str() << endl;

    char* result_cstr = strdup(result.c_str());
    return result_cstr;

}
const char* sha256(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-256
    const EVP_MD* md = EVP_sha256();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-256
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
            cout << "Hashed: " << ss.str() << endl;

    char* result_cstr = strdup(result.c_str());
    return result_cstr;

}
const char* sha384(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-256
    const EVP_MD* md = EVP_sha3_384();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-256
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
            cout << "Hashed: " << ss.str() << endl;

    char* result_cstr = strdup(result.c_str());
    return result_cstr;

}
const char* sha512(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-512
    const EVP_MD* md = EVP_sha512();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-512
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
            cout << "Hashed: " << ss.str() << endl;

        char* result_cstr = strdup(result.c_str());
        return result_cstr;

}
const char* SHA3_224(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-256
    const EVP_MD* md = EVP_sha3_224();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-256
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
        cout << "Hashed: " << ss.str() << endl;
        char* result_cstr = strdup(result.c_str());
        return result_cstr;

}
const char* SHA3_256(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-256
    const EVP_MD* md = EVP_sha3_256();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-256
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
    cout << "Hashed: " << ss.str() << endl;
    char* result_cstr = strdup(result.c_str());
    return result_cstr;

}
const char* SHA3_384(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA-256
    const EVP_MD* md = EVP_sha3_384();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA-256
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
    std::string result = ss.str();
            cout << "Hashed: " << ss.str() << endl;

    char* result_cstr = strdup(result.c_str());
    return result_cstr;
}
const char* SHA3_512(const char *Input , const char *Inputfile  ,const char* Outputfile ) {
    // Tạo một ngữ cảnh băm
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHA3-512
    const EVP_MD* md = EVP_sha3_512();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_sha224 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHA3-512
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length_of_hash) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    if(outputfile != "0")
    {
        std::string hash_hex = ss.str();

    // Mở file để ghi kết quả băm
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Ghi kết quả băm vào file
    outfile << hash_hex;
    outfile.close();

    }
   std::string result = ss.str();
            cout << "Hashed: " << ss.str() << endl;

    char* result_cstr = strdup(result.c_str());
    return result_cstr;
}
const char* shake128(const char *Input , const char *Inputfile  ,const char* Outputfile, const char * Digestlength) {
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    int digest_length =  stoi(Digestlength);
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    // Tạo một ngữ cảnh băm
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHAKE128
    const EVP_MD* md = EVP_shake128();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_shake128 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHAKE128
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm với độ dài digest_length
    std::vector<unsigned char> hash(digest_length);
    if (EVP_DigestFinalXOF(mdctx, hash.data(), digest_length) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinalXOF failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    std::stringstream ss;
    for (unsigned int i = 0; i < digest_length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::string hash_hex = ss.str();

    // Ghi kết quả băm vào file nếu outputfile không rỗng
    if (outputfile != "0") {
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
            throw std::runtime_error("Failed to open output file for writing");
        }
        outfile << hash_hex;
        outfile.close();
    }

    
    cout << "Hashed: " << hash_hex << endl;
    char* result_cstr = strdup(hash_hex.c_str());
    return result_cstr;
}
const char* shake256(const char *Input , const char *Inputfile  ,const char* Outputfile, const char * Digestlength ) {
    string input = Input;
    string inputfile = Inputfile;
    string outputfile = Outputfile;
    int digest_length =  stoi(Digestlength);
    std::string data = input;

    // Đọc nội dung từ file nếu input là rỗng và inputfile không rỗng
    if (data == "0" && inputfile != "0") {
        std::ifstream inpfile(inputfile);
        if (!inpfile.is_open()) {
            throw std::runtime_error("Failed to open input file for reading");
        }
        std::stringstream buffer;
        buffer << inpfile.rdbuf();
        data = buffer.str();
        inpfile.close();
    }

    // Tạo một ngữ cảnh băm
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Lấy thuật toán SHAKE128
    const EVP_MD* md = EVP_shake256();
    if (md == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_shake128 failed");
    }

    // Khởi tạo ngữ cảnh băm với thuật toán SHAKE128
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Cập nhật ngữ cảnh băm với dữ liệu đầu vào
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Lấy kết quả băm với độ dài digest_length
    std::vector<unsigned char> hash(digest_length);
    if (EVP_DigestFinalXOF(mdctx, hash.data(), digest_length) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinalXOF failed");
    }

    // Giải phóng ngữ cảnh băm
    EVP_MD_CTX_free(mdctx);

    // Chuyển đổi kết quả băm thành chuỗi hex
    std::stringstream ss;
    for (unsigned int i = 0; i < digest_length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::string hash_hex = ss.str();

    // Ghi kết quả băm vào file nếu outputfile không rỗng
    if (outputfile != "0") {
        std::ofstream outfile(outputfile);
        if (!outfile.is_open()) {
            throw std::runtime_error("Failed to open output file for writing");
        }
        outfile << hash_hex;
        outfile.close();
    }

    cout << "1" << "-" << hash_hex;
    cout << "Hashed: " << hash_hex << endl;
    char* result_cstr = strdup(hash_hex.c_str());
    return result_cstr;
}
int main(int argc, char *argv[]) {
    std::string algo =  argv[1];
    std::string input =  argv[2];
    std::string inputfile =  argv[3];
    std::string outputfile = argv[4];
    int digestlength;
    clock_t start, end;
    double duration;
    start = clock();
    
    if (algo == "SHA224") {
        sha224(argv[2], argv[3], argv[4]);
    } else if (algo == "SHA256") {
        sha256(argv[2], argv[3], argv[4]);
    } else if (algo == "SHA384") {
       sha384(argv[2], argv[3], argv[4]);
    } else if (algo == "SHA512") {
         sha512(argv[2], argv[3], argv[4]);
    } else if (algo == "SHA3-224") {
        SHA3_224(argv[2], argv[3], argv[4]);
    } else if (algo == "SHA3-256") {
        SHA3_256(argv[2], argv[3], argv[4]);
    } else if( algo == "SHA3-384") {
        SHA3_384(argv[2], argv[3], argv[4]);
    }
     else if (algo == "SHA3-512") {
       SHA3_512(argv[2], argv[3], argv[4]);
    } else if (algo == "SHAKE128") {
        
        if (argc > 5) {
            digestlength = stoi(argv[5]);
        }
         shake128(argv[2], argv[3], argv[4], argv[5]);
    } else if (algo == "SHAKE256") {
        if (argc > 5) {
            digestlength = stoi(argv[5]);
        }
         shake256(argv[2], argv[3], argv[4], argv[5]);
    }
    end = clock();
    duration = ((double)(end - start)) / CLOCKS_PER_SEC;
    cout << "Duration: " << duration << endl;
    return 0;
}
