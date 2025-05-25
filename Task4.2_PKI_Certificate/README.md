# Công cụ Phân tích Chứng chỉ X.509

Công cụ này cho phép phân tích các trường của chứng chỉ X.509, bao gồm tên chủ thể, tên người phát hành, khóa công khai, chữ ký, thuật toán chữ ký và các tham số, mục đích sử dụng, thời hạn hiệu lực và nhiều thông tin khác.

## Yêu cầu

- OpenSSL
- Trình biên dịch C++ (g++)

## Biên dịch

```bash
make
```

## Cách sử dụng

```bash
./certificate_parser [tùy chọn]
```

### Tùy chọn

- `-h, --help`: Hiển thị trợ giúp
- `-f, --file FILENAME`: Đường dẫn đến tập tin chứng chỉ
- `-t, --type TYPE`: Loại tập tin (PEM hoặc DER, mặc định là PEM)
- `-o, --output FILENAME`: Ghi khóa công khai vào tập tin (nếu chữ ký hợp lệ)

### Ví dụ

```bash
# Phân tích chứng chỉ PEM
./certificate_parser -f certificate.pem

# Phân tích chứng chỉ DER
./certificate_parser -f certificate.der -t DER

# Phân tích chứng chỉ và lưu khóa công khai
./certificate_parser -f certificate.pem -o pubkey.pem
```

## Kết quả

Công cụ sẽ hiển thị thông tin chi tiết về chứng chỉ và trả về khóa công khai nếu chữ ký hợp lệ, nếu không sẽ trả về null.
