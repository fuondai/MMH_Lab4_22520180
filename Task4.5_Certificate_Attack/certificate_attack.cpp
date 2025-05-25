#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

// Hàm hiển thị lỗi OpenSSL
void handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
}

// Hàm tạo khóa RSA
EVP_PKEY* generateRSAKey(int bits) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    if (!RSA_generate_key_ex(rsa, bits, e, nullptr)) {
        handleOpenSSLErrors();
        return nullptr;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(e);
    return pkey;
}

// Hàm tạo chứng chỉ X.509 (ký bằng MD5)
X509* generateCertificate(EVP_PKEY* pkey, const std::string& subject, int days) {
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * days);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    std::istringstream ss(subject);
    std::string token;

    while (std::getline(ss, token, ',')) {
        size_t pos = token.find('=');
        if (pos != std::string::npos) {
            std::string field = token.substr(0, pos);
            std::string value = token.substr(pos + 1);
            field.erase(0, field.find_first_not_of(" "));
            field.erase(field.find_last_not_of(" ") + 1);
            value.erase(0, value.find_first_not_of(" "));
            value.erase(value.find_last_not_of(" ") + 1);

            X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC,
                                       (const unsigned char*)value.c_str(), -1, -1, 0);
        }
    }

    X509_set_issuer_name(cert, name);
    if (!X509_sign(cert, pkey, EVP_md5())) {
        handleOpenSSLErrors();
        return nullptr;
    }

    return cert;
}

// Hàm lưu chứng chỉ ra file
bool saveCertificate(X509* cert, const std::string& filename, bool isPEM = true) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file) return false;

    bool success = isPEM ? PEM_write_X509(file, cert) : i2d_X509_fp(file, cert);
    fclose(file);
    return success;
}

// Hàm lưu khóa riêng tư ra file
bool savePrivateKey(EVP_PKEY* pkey, const std::string& filename, bool isPEM = true) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file) return false;

    bool success = isPEM ? PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr)
                         : i2d_PrivateKey_fp(file, pkey);
    fclose(file);
    return success;
}

// Tạo file prefix (tiền tố) cho md5_fastcoll
void createPrefixForCollision(const std::string& filename, const std::string& prefix) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Không thể tạo file prefix.");
    file.write(prefix.c_str(), prefix.size());
    file.close();
}

// Chạy md5_fastcoll để tạo collision
bool run_md5_fastcoll(const std::string& prefix_file,
                      const std::string& output1, const std::string& output2) {
    std::string tool = "md5_fastcoll";
    std::string command = tool + " -p " + prefix_file + " -o " + output1 + " " + output2;

    std::cout << "[*] Đang chạy: " << command << std::endl;
    int ret = system(command.c_str());

    return ret == 0;
}

// MAIN: Sinh chứng chỉ và chạy md5 collision
int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::string subject1 = "C=VN, ST=HCM, L=ThuDuc, O=UIT, OU=CS, CN=Alice, emailAddress=alice@example.com";
    std::string prefixFile = "prefix.bin";
    std::string coll1 = "collision1.bin";
    std::string coll2 = "collision2.bin";

    EVP_PKEY* pkey = generateRSAKey(1024);
    if (!pkey) {
        std::cerr << "Không tạo được khóa RSA\n";
        return 1;
    }

    X509* cert = generateCertificate(pkey, subject1, 365);
    if (!cert) {
        std::cerr << "Không tạo được chứng chỉ\n";
        EVP_PKEY_free(pkey);
        return 1;
    }

    std::cout << "[*] Lưu chứng chỉ và khóa riêng tư..." << std::endl;
    saveCertificate(cert, "cert.pem");
    savePrivateKey(pkey, "private.pem");

    std::cout << "[*] Tạo prefix cho md5 collision..." << std::endl;
    std::ostringstream oss;
    PEM_write_X509(stdout, cert); // In ra stdout cho demo

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    createPrefixForCollision(prefixFile, std::string(mem->data, mem->length));
    BIO_free(bio);

    std::cout << "[*] Đang tạo file collision..." << std::endl;
    if (run_md5_fastcoll(prefixFile, coll1, coll2)) {
        std::cout << "[+] Thành công! Tạo 2 file có cùng MD5: " << coll1 << " và " << coll2 << std::endl;
    } else {
        std::cerr << "[-] Thất bại khi tạo collision.\n";
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}

