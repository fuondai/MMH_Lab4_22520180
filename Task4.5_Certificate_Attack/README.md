# Công cụ mô phỏng tấn công trên chứng chỉ số

Công cụ này mô phỏng tấn công trên chứng chỉ X.509 sử dụng MD5 và RSA, cho phép tạo ra hai chứng chỉ với tên chủ thể khác nhau nhưng có cùng chữ ký số.

## Yêu cầu

- OpenSSL
- Trình biên dịch C++ (g++)
- Hashclash (tùy chọn, cho tấn công collision thực sự)

## Biên dịch

```bash
make
```

## Sử dụng

```bash
./certificate_attack [tùy chọn]
```

### Tùy chọn

- `-h, --help`: Hiển thị trợ giúp
- `-s1, --subject1 SUBJECT`: Tên chủ thể cho chứng chỉ 1
- `-s2, --subject2 SUBJECT`: Tên chủ thể cho chứng chỉ 2
- `-o1, --output1 FILENAME`: Tên file cho chứng chỉ 1
- `-o2, --output2 FILENAME`: Tên file cho chứng chỉ 2
- `-r, --run-hashclash`: Chạy hashclash để tạo collision

### Ví dụ

```bash
# Tạo hai chứng chỉ với tên chủ thể khác nhau
./certificate_attack -s1 "C=VN, ST=Hanoi, L=Hanoi, O=Example Inc, OU=IT, CN=example.com, emailAddress=admin@example.com" \
                   -s2 "C=VN, ST=Hanoi, L=Hanoi, O=Attacker Inc, OU=Hack, CN=attacker.com, emailAddress=admin@attacker.com" \
                   -o1 certificate1.pem -o2 certificate2.pem

# Chạy với hashclash để tạo collision
./certificate_attack -s1 "C=VN, ST=Hanoi, L=Hanoi, O=Example Inc, OU=IT, CN=example.com, emailAddress=admin@example.com" \
                   -s2 "C=VN, ST=Hanoi, L=Hanoi, O=Attacker Inc, OU=Hack, CN=attacker.com, emailAddress=admin@attacker.com" \
                   -o1 certificate1.pem -o2 certificate2.pem -r
```
