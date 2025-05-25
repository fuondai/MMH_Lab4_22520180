#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <locale>
#include <codecvt>

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <io.h>
#include <fcntl.h>
#define SET_BINARY_MODE(file) _setmode(_fileno(file), _O_BINARY)
#else
#define SET_BINARY_MODE(file)
#endif

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Hàm để hiển thị lỗi OpenSSL
void handleOpenSSLErrors()
{
    ERR_print_errors_fp(stderr);
}

// Hàm để chuyển đổi ASN1_TIME sang chuỗi dễ đọc
std::string ASN1TimeToString(ASN1_TIME *time)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, time);

    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    BIO_read(bio, buffer, sizeof(buffer) - 1);
    BIO_free(bio);

    return std::string(buffer);
}

// Hàm để chuyển đổi X509_NAME sang chuỗi dễ đọc
std::string X509NameToString(X509_NAME *name)
{
    BIO *bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE);

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    BIO_read(bio, buffer, sizeof(buffer) - 1);
    BIO_free(bio);

    return std::string(buffer);
}

// Hàm để chuyển đổi khóa công khai sang chuỗi PEM
std::string PublicKeyToString(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    char *buffer = nullptr;
    long size = BIO_get_mem_data(bio, &buffer);
    std::string result(buffer, size);
    BIO_free(bio);

    return result;
}

// Hàm để kiểm tra chữ ký của chứng chỉ
bool verifySignature(X509 *cert)
{
    EVP_PKEY *pubKey = X509_get_pubkey(cert);
    if (!pubKey)
    {
        std::cerr << "Could not extract public key from certificate" << std::endl;
        return false;
    }

    int result = X509_verify(cert, pubKey);
    EVP_PKEY_free(pubKey);

    return result > 0;
}

// Hàm để phân tích và hiển thị thông tin chứng chỉ X.509
EVP_PKEY *parseCertificate(const std::string &filename, bool isPEM)
{
    X509 *cert = nullptr;

    // Đọc toàn bộ file vào bộ nhớ để tránh lỗi OPENSSL_Applink
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Cannot open file: " << filename << std::endl;
        return nullptr;
    }

    // Đọc nội dung file vào buffer
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(fileSize);
    file.read(reinterpret_cast<char *>(buffer.data()), fileSize);
    file.close();

    // Tạo BIO từ bộ nhớ
    BIO *bio = BIO_new_mem_buf(buffer.data(), fileSize);
    if (!bio)
    {
        std::cerr << "Cannot create BIO" << std::endl;
        handleOpenSSLErrors();
        return nullptr;
    }

    // Đọc chứng chỉ từ BIO
    if (isPEM)
    {
        cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    }
    else
    {
        cert = d2i_X509_bio(bio, nullptr);
    }

    BIO_free(bio);

    if (!cert)
    {
        std::cerr << "Cannot read certificate from file" << std::endl;
        handleOpenSSLErrors();
        return nullptr;
    }

    // Hiển thị thông tin chứng chỉ
    std::cout << "=== X.509 Certificate Information ===" << std::endl;

    // Version
    long version = X509_get_version(cert);
    std::cout << "Version: " << version + 1 << std::endl;

    // Serial Number
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    std::cout << "Serial Number: ";
    for (int i = 0; i < serial->length; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(serial->data[i]);
    }
    std::cout << std::dec << std::endl;

    // Tên người phát hành
    X509_NAME *issuerName = X509_get_issuer_name(cert);
    std::cout << "Issuer Name: " << X509NameToString(issuerName) << std::endl;

    // Thời gian hiệu lực
    std::cout << "Valid From: " << ASN1TimeToString(X509_get_notBefore(cert)) << std::endl;
    std::cout << "Valid To: " << ASN1TimeToString(X509_get_notAfter(cert)) << std::endl;

    // Tên chủ thể
    X509_NAME *subjectName = X509_get_subject_name(cert);
    std::cout << "Subject Name: " << X509NameToString(subjectName) << std::endl;

    // Signature Algorithm
    int sig_nid = X509_get_signature_nid(cert);
    std::cout << "Signature Algorithm: " << OBJ_nid2ln(sig_nid) << " (" << OBJ_nid2sn(sig_nid) << ")" << std::endl;

    // Public Key
    EVP_PKEY *pubKey = X509_get_pubkey(cert);
    if (pubKey)
    {
        int keyType = EVP_PKEY_base_id(pubKey);
        std::cout << "Public Key Type: " << OBJ_nid2ln(keyType) << " (" << OBJ_nid2sn(keyType) << ")" << std::endl;

        // Key Size
        int keyBits = EVP_PKEY_bits(pubKey);
        std::cout << "Key Size: " << keyBits << " bits" << std::endl;

        // Hiển thị public key dạng PEM format
        std::cout << "\nPublic Key (PEM):\n"
                  << PublicKeyToString(pubKey) << std::endl;
    }

    // Signature Verification
    bool isValid = verifySignature(cert);
    std::cout << "Signature Status: " << (isValid ? "Valid" : "Invalid") << std::endl;

    // Key Usage and Extensions
    std::cout << "Certificate Purposes:" << std::endl;

    // Kiểm tra Extensions
    int extCount = X509_get_ext_count(cert);
    for (int i = 0; i < extCount; i++)
    {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

        char extname[256];
        OBJ_obj2txt(extname, sizeof(extname), obj, 0);

        // Kiểm tra Extended Key Usage
        if (strcmp(extname, "extendedKeyUsage") == 0 || strcmp(extname, "2.5.29.37") == 0)
        {
            BIO *bio = BIO_new(BIO_s_mem());
            X509V3_EXT_print(bio, ext, 0, 0);

            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));
            BIO_read(bio, buffer, sizeof(buffer) - 1);
            BIO_free(bio);

            std::cout << "  - Extended Key Usage: " << buffer << std::endl;
        }
        // Kiểm tra Key Usage
        else if (strcmp(extname, "keyUsage") == 0 || strcmp(extname, "2.5.29.15") == 0)
        {
            BIO *bio = BIO_new(BIO_s_mem());
            X509V3_EXT_print(bio, ext, 0, 0);

            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));
            BIO_read(bio, buffer, sizeof(buffer) - 1);
            BIO_free(bio);

            std::cout << "  - Key Usage: " << buffer << std::endl;
        }
    }

    // Trả về khóa công khai nếu chữ ký hợp lệ, nếu không trả về nullptr
    if (!isValid)
    {
        std::cout << "Signature invalid, returning nullptr instead of public key" << std::endl;
        EVP_PKEY_free(pubKey);
        X509_free(cert);
        return nullptr;
    }

    // Giải phóng bộ nhớ chứng chỉ
    X509_free(cert);

    return pubKey;
}

void printUsage()
{
    std::cout << "Usage: ./certificate_parser [options]\n"
              << "Options:\n"
              << "  -h, --help                  Display this help\n"
              << "  -f, --file FILENAME         Path to certificate file\n"
              << "  -t, --type TYPE             File type (PEM or DER, default is PEM)\n"
              << "  -o, --output FILENAME       Write public key to file (if signature is valid)\n"
              << std::endl;
}

int main(int argc, char *argv[])
{
    // Khởi tạo OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::string certFile;
    std::string outputFile;
    bool isPEM = true;

    // Phân tích đối số dòng lệnh
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help")
        {
            printUsage();
            return 0;
        }
        else if (arg == "-f" || arg == "--file")
        {
            if (i + 1 < argc)
            {
                certFile = argv[++i];
            }
            else
            {
                std::cerr << "Error: Missing argument for " << arg << std::endl;
                return 1;
            }
        }
        else if (arg == "-t" || arg == "--type")
        {
            if (i + 1 < argc)
            {
                std::string type = argv[++i];
                if (type == "DER" || type == "der")
                {
                    isPEM = false;
                }
                else if (type != "PEM" && type != "pem")
                {
                    std::cerr << "Error: Invalid file type. Use PEM or DER." << std::endl;
                    return 1;
                }
            }
            else
            {
                std::cerr << "Error: Missing argument for " << arg << std::endl;
                return 1;
            }
        }
        else if (arg == "-o" || arg == "--output")
        {
            if (i + 1 < argc)
            {
                outputFile = argv[++i];
            }
            else
            {
                std::cerr << "Error: Missing argument for " << arg << std::endl;
                return 1;
            }
        }
    }

    if (certFile.empty())
    {
        std::cerr << "Error: Certificate file must be specified" << std::endl;
        printUsage();
        return 1;
    }

    // Phân tích chứng chỉ
    EVP_PKEY *pubKey = parseCertificate(certFile, isPEM);

    // Nếu chữ ký hợp lệ và yêu cầu lưu file
    if (pubKey && !outputFile.empty())
    {
        FILE *file = fopen(outputFile.c_str(), "w");
        if (file)
        {
            PEM_write_PUBKEY(file, pubKey);
            fclose(file);
            std::cout << "Public key saved to file: " << outputFile << std::endl;
        }
        else
        {
            std::cerr << "Cannot open file for writing: " << outputFile << std::endl;
        }
    }

    // Giải phóng bộ nhớ
    if (pubKey)
    {
        EVP_PKEY_free(pubKey);
    }

    // Clean OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
