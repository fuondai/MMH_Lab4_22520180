#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <chrono>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <openssl/evp.h>

// Hàm để đọc văn bản từ file với hỗ trợ UTF-8
std::string readFromFile(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Đọc toàn bộ nội dung file
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Hàm để chuyển đổi digest thành chuỗi hex
std::string digestToHexString(const unsigned char *digest, size_t digestSize)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < digestSize; i++)
    {
        ss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return ss.str();
}

// Hàm để lưu digest vào file
void saveToFile(const std::string &filename, const std::string &content)
{
    std::ofstream file(filename);
    if (!file)
    {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    file << content;
}

// Hàm để tính toán SHA224
std::string calculateSHA224(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA224::DIGESTSIZE];
    CryptoPP::SHA224 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA224::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA256
std::string calculateSHA256(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA256::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA384
std::string calculateSHA384(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA384::DIGESTSIZE];
    CryptoPP::SHA384 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA384::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA512
std::string calculateSHA512(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA512::DIGESTSIZE];
    CryptoPP::SHA512 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA512::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA3-224
std::string calculateSHA3_224(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA3_224::DIGESTSIZE];
    CryptoPP::SHA3_224 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA3_224::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA3-256
std::string calculateSHA3_256(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA3_256::DIGESTSIZE];
    CryptoPP::SHA3_256 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA3_256::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA3-384
std::string calculateSHA3_384(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA3_384::DIGESTSIZE];
    CryptoPP::SHA3_384 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA3_384::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHA3-512
std::string calculateSHA3_512(const std::string &input)
{
    CryptoPP::byte digest[CryptoPP::SHA3_512::DIGESTSIZE];
    CryptoPP::SHA3_512 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte *)input.data(), input.size());

    std::string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(digest, CryptoPP::SHA3_512::DIGESTSIZE);
    encoder.MessageEnd();
    return output;
}

// Hàm để tính toán SHAKE128 sử dụng OpenSSL
std::string calculateSHAKE128(const std::string &input, size_t digestLength)
{
    unsigned char *digest = new unsigned char[digestLength];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
    {
        delete[] digest;
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw std::runtime_error("Failed to initialize SHAKE128");
    }

    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw std::runtime_error("Error updating data for SHAKE128");
    }

    if (EVP_DigestFinalXOF(ctx, digest, digestLength) != 1)
    {
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw std::runtime_error("Error finalizing SHAKE128");
    }

    EVP_MD_CTX_free(ctx);

    std::string result = digestToHexString(digest, digestLength);
    delete[] digest;

    return result;
}

// Hàm để tính toán SHAKE256 sử dụng OpenSSL
std::string calculateSHAKE256(const std::string &input, size_t digestLength)
{
    unsigned char *digest = new unsigned char[digestLength];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
    {
        delete[] digest;
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw std::runtime_error("Failed to initialize SHAKE256");
    }

    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw std::runtime_error("Error updating data for SHAKE256");
    }

    if (EVP_DigestFinalXOF(ctx, digest, digestLength) != 1)
    {
        EVP_MD_CTX_free(ctx);
        delete[] digest;
        throw std::runtime_error("Error finalizing SHAKE256");
    }

    EVP_MD_CTX_free(ctx);

    std::string result = digestToHexString(digest, digestLength);
    delete[] digest;

    return result;
}

// Hàm để đo thời gian thực thi
template <typename Func, typename... Args>
std::pair<std::string, double> measureExecutionTime(Func func, Args &&...args)
{
    auto start = std::chrono::high_resolution_clock::now();
    std::string result = func(std::forward<Args>(args)...);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    return {result, duration.count()};
}

void printUsage()
{
    std::cout << "Usage: ./hash_functions [options]\n"
              << "Options:\n"
              << "  -h, --help                  Display this help message\n"
              << "  -a, --algorithm ALGORITHM   Select hash algorithm (SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256)\n"
              << "  -i, --input TEXT            Input text\n"
              << "  -f, --file FILENAME         Read input from file\n"
              << "  -o, --output FILENAME       Write output to file\n"
              << "  -d, --digest-length LENGTH  Digest length for SHAKE128/SHAKE256 (default: 32)\n"
              << "  -b, --benchmark             Run benchmark for all algorithms\n"
              << "  -s, --size SIZE             Input size for benchmark (MB)\n"
              << std::endl;
}

int main(int argc, char *argv[])
{
    // Khởi tạo OpenSSL
    OpenSSL_add_all_digests();

    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::string algorithm;
    std::string input;
    std::string inputFile;
    std::string outputFile;
    size_t digestLength = 32;
    bool benchmark = false;
    size_t benchmarkSize = 1; // MB

    // Phân tích tham số dòng lệnh
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help")
        {
            printUsage();
            return 0;
        }
        else if (arg == "-a" || arg == "--algorithm")
        {
            if (i + 1 < argc)
            {
                algorithm = argv[++i];
            }
            else
            {
                std::cerr << "Error: Missing parameter for " << arg << std::endl;
                return 1;
            }
        }
        else if (arg == "-i" || arg == "--input")
        {
            if (i + 1 < argc)
            {
                input = argv[++i];
            }
            else
            {
                std::cerr << "Error: Missing parameter for " << arg << std::endl;
                return 1;
            }
        }
        else if (arg == "-f" || arg == "--file")
        {
            if (i + 1 < argc)
            {
                inputFile = argv[++i];
            }
            else
            {
                std::cerr << "Error: Missing parameter for " << arg << std::endl;
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
                std::cerr << "Error: Missing parameter for " << arg << std::endl;
                return 1;
            }
        }
        else if (arg == "-d" || arg == "--digest-length")
        {
            if (i + 1 < argc)
            {
                digestLength = std::stoul(argv[++i]);
            }
            else
            {
                std::cerr << "Error: Missing parameter for " << arg << std::endl;
                return 1;
            }
        }
        else if (arg == "-b" || arg == "--benchmark")
        {
            benchmark = true;
        }
        else if (arg == "-s" || arg == "--size")
        {
            if (i + 1 < argc)
            {
                benchmarkSize = std::stoul(argv[++i]);
            }
            else
            {
                std::cerr << "Error: Missing parameter for " << arg << std::endl;
                return 1;
            }
        }
    }

    try
    {
        // Nếu không có đầu vào từ tham số hoặc file, yêu cầu người dùng nhập
        if (input.empty() && inputFile.empty() && !benchmark)
        {
            std::cout << "Enter text (UTF-8 supported): ";
            std::getline(std::cin, input);
        }

        // Đọc từ file nếu được chỉ định
        if (!inputFile.empty() && !benchmark)
        {
            input = readFromFile(inputFile);
        }

        // Chế độ benchmark
        if (benchmark)
        {
            // Tạo dữ liệu đầu vào cho benchmark
            const size_t dataSize = benchmarkSize * 1024 * 1024; // Chuyển đổi MB thành bytes
            std::string benchmarkData(dataSize, 'A');

            std::cout << "Running benchmark with input size " << benchmarkSize << " MB:" << std::endl;
            std::cout << std::left << std::setw(15) << "Algorithm" << std::setw(20) << "Time (ms)" << std::endl;
            std::cout << std::string(35, '-') << std::endl;

            auto [sha224Result, sha224Time] = measureExecutionTime(calculateSHA224, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA224" << std::setw(20) << sha224Time << std::endl;

            auto [sha256Result, sha256Time] = measureExecutionTime(calculateSHA256, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA256" << std::setw(20) << sha256Time << std::endl;

            auto [sha384Result, sha384Time] = measureExecutionTime(calculateSHA384, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA384" << std::setw(20) << sha384Time << std::endl;

            auto [sha512Result, sha512Time] = measureExecutionTime(calculateSHA512, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA512" << std::setw(20) << sha512Time << std::endl;

            auto [sha3_224Result, sha3_224Time] = measureExecutionTime(calculateSHA3_224, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA3-224" << std::setw(20) << sha3_224Time << std::endl;

            auto [sha3_256Result, sha3_256Time] = measureExecutionTime(calculateSHA3_256, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA3-256" << std::setw(20) << sha3_256Time << std::endl;

            auto [sha3_384Result, sha3_384Time] = measureExecutionTime(calculateSHA3_384, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA3-384" << std::setw(20) << sha3_384Time << std::endl;

            auto [sha3_512Result, sha3_512Time] = measureExecutionTime(calculateSHA3_512, benchmarkData);
            std::cout << std::left << std::setw(15) << "SHA3-512" << std::setw(20) << sha3_512Time << std::endl;

            auto [shake128Result, shake128Time] = measureExecutionTime(calculateSHAKE128, benchmarkData, digestLength);
            std::cout << std::left << std::setw(15) << "SHAKE128" << std::setw(20) << shake128Time << std::endl;

            auto [shake256Result, shake256Time] = measureExecutionTime(calculateSHAKE256, benchmarkData, digestLength);
            std::cout << std::left << std::setw(15) << "SHAKE256" << std::setw(20) << shake256Time << std::endl;

            return 0;
        }

        // Tính toán hash dựa trên thuật toán được chọn
        std::string result;
        if (algorithm == "SHA224")
        {
            result = calculateSHA224(input);
        }
        else if (algorithm == "SHA256")
        {
            result = calculateSHA256(input);
        }
        else if (algorithm == "SHA384")
        {
            result = calculateSHA384(input);
        }
        else if (algorithm == "SHA512")
        {
            result = calculateSHA512(input);
        }
        else if (algorithm == "SHA3-224")
        {
            result = calculateSHA3_224(input);
        }
        else if (algorithm == "SHA3-256")
        {
            result = calculateSHA3_256(input);
        }
        else if (algorithm == "SHA3-384")
        {
            result = calculateSHA3_384(input);
        }
        else if (algorithm == "SHA3-512")
        {
            result = calculateSHA3_512(input);
        }
        else if (algorithm == "SHAKE128")
        {
            result = calculateSHAKE128(input, digestLength);
        }
        else if (algorithm == "SHAKE256")
        {
            result = calculateSHAKE256(input, digestLength);
        }
        else
        {
            std::cerr << "Error: Algorithm not supported or not specified" << std::endl;
            printUsage();
            return 1;
        }

        // In kết quả ra màn hình hoặc lưu vào file
        if (outputFile.empty())
        {
            std::cout << "Result (" << algorithm << "): " << result << std::endl;
        }
        else
        {
            saveToFile(outputFile, result);
            std::cout << "Result saved to file: " << outputFile << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    // Dọn dẹp OpenSSL
    EVP_cleanup();

    return 0;
}
