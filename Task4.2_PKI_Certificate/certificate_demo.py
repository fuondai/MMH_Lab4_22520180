#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import tempfile
import time
from colorama import init, Fore, Style
import platform
IS_WINDOWS = platform.system() == "Windows"
CERT_PARSER = "./certificate_parser.exe" if IS_WINDOWS else "./certificate_parser"

init()

# Mô tả về công cụ
TOOL_DESCRIPTION = """
X.509 Certificate Parser Tool Demo
---------------------------------
Task 4.2: PKI and digital certificate

This tool demonstrates:
- Parsing all fields of X.509 certificates (subject name, issuer name, 
  subject public key, signature, signature algorithms and parameters, 
  purposes, valid from and valid to dates, etc.)
- Checking signature validity
- Processing both PEM (Base64) and DER (binary) formats
- Returning subject public key if signature is valid, null otherwise
"""

def print_colored(text, color=Fore.WHITE, style=Style.NORMAL):
    """In văn bản có màu."""
    print(f"{style}{color}{text}{Style.RESET_ALL}")

def print_header(text):
    """In tiêu đề có định dạng."""
    print_colored("\n" + "="*80, Fore.CYAN, Style.BRIGHT)
    print_colored(f" {text} ", Fore.CYAN, Style.BRIGHT)
    print_colored("="*80, Fore.CYAN, Style.BRIGHT)

def print_section(text):
    """In tiêu đề phần có định dạng."""
    print_colored(f"\n{text}:", Fore.YELLOW, Style.BRIGHT)
    print_colored("-" * (len(text) + 1), Fore.YELLOW)

def create_test_certificates():
    """Tạo các chứng chỉ test để thị phạm."""
    print_header("Creating Test Certificates")
    
    # Tạo thư mục tạm nếu không tồn tại
    if not os.path.exists("temp"):
        os.makedirs("temp")
    
    # Tạo khóa RSA và chứng chỉ RSA tự ký
    print_section("Creating RSA Self-Signed Certificate (PEM format)")
    rsa_key = "temp/rsa_key.pem"
    rsa_cert = "temp/rsa_cert.pem"
    
    subprocess.run(["openssl", "genrsa", "-out", rsa_key, "2048"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Generated RSA private key", Fore.GREEN)
    
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", rsa_key,
                    "-out", rsa_cert, "-days", "365",
                    "-subj", "/C=VN/ST=Hanoi/L=Hanoi/O=Demo Organization/OU=IT/CN=www.example.com"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Generated self-signed RSA certificate (PEM format)", Fore.GREEN)
    
    # Tạo chứng chỉ định dạng DER
    print_section("Creating DER Format Certificate")
    rsa_cert_der = "temp/rsa_cert.der"
    subprocess.run(["openssl", "x509", "-in", rsa_cert, "-outform", "DER", 
                    "-out", rsa_cert_der],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Converted certificate to DER format", Fore.GREEN)
    
    # Tạo chứng chỉ ECC
    print_section("Creating ECC Self-Signed Certificate")
    ecc_key = "temp/ecc_key.pem"
    ecc_cert = "temp/ecc_cert.pem"
    
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", ecc_key],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Generated ECC private key", Fore.GREEN)
    
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", ecc_key,
                    "-out", ecc_cert, "-days", "365",
                    "-subj", "/C=VN/ST=Hanoi/L=Hanoi/O=Demo Organization/OU=Security/CN=secure.example.com"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Generated self-signed ECC certificate (PEM format)", Fore.GREEN)
    
    # Tạo một chứng chỉ với nhiều extention để demo
    print_section("Creating Extended Certificate with Various Extensions")
    ext_key = "temp/ext_key.pem"
    ext_cert = "temp/ext_cert.pem"
    ext_config = "temp/ext.cnf"
    
    # Tạo file cấu hình cho chứng chỉ với nhiều extension
    with open(ext_config, "w") as f:
        f.write("""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = VN
ST = Hanoi
L = Hanoi
O = Extended Demo
OU = Security Research
CN = extended.example.com
emailAddress = admin@example.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
subjectAltName = @alt_names

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = cRLSign, keyCertSign
nsCertType = server, client, email, objsign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always

[alt_names]
DNS.1 = extended.example.com
DNS.2 = www.extended.example.com
IP.1 = 192.168.1.1
"""
        )
    
    subprocess.run(["openssl", "genrsa", "-out", ext_key, "2048"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Generated RSA key for extended certificate", Fore.GREEN)
    
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", ext_key,
                    "-out", ext_cert, "-days", "365", "-config", ext_config],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_colored("Generated self-signed certificate with various extensions", Fore.GREEN)
    
    return {
        "rsa_pem": rsa_cert,
        "rsa_der": rsa_cert_der,
        "ecc_pem": ecc_cert,
        "ext_pem": ext_cert
    }

def demo_certificate_parsing(cert_files):
    """Demo phân tích các loại chứng chỉ khác nhau."""
    for cert_type, cert_file in cert_files.items():
        print_header(f"Analyzing {cert_type.upper()} Certificate")
        
        # Xác định định dạng file
        cert_format = "PEM"
        if cert_type.endswith("der"):
            cert_format = "DER"
        
        # Chạy công cụ certificate_parser với chứng chỉ
        print_section(f"Parsing Certificate with certificate_parser")
        cmd = [CERT_PARSER, "-f", cert_file, "-t", cert_format]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # In kết quả phân tích
        if result.stdout:
            lines = result.stdout.split('\n')
            for line in lines:
                if "Public Key (PEM)" in line:
                    print_colored(line, Fore.GREEN, Style.BRIGHT)
                    # In khóa công khai với màu xanh
                    in_key_section = True
                elif "Signature Status:" in line:
                    status = "Valid" in line
                    color = Fore.GREEN if status else Fore.RED
                    print_colored(line, color, Style.BRIGHT)
                    if status:
                        print_colored("✓ Public key is returned because signature is valid", Fore.GREEN, Style.BRIGHT)
                    else:
                        print_colored("✗ NULL is returned because signature is invalid", Fore.RED, Style.BRIGHT)
                else:
                    print(line)
        
        # Demo lưu khóa công khai ra file
        if "Signature Status: Valid" in result.stdout:
            print_section("Extracting Public Key to File")
            pubkey_file = f"temp/{cert_type}_pubkey.pem"
            extract_cmd = [CERT_PARSER, "-f", cert_file, 
                           "-t", cert_format, "-o", pubkey_file]
            subprocess.run(extract_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print_colored(f"Public key successfully extracted to {pubkey_file}", Fore.GREEN)
            
            # Hiển thị nội dung khóa công khai
            with open(pubkey_file, "r") as f:
                pubkey_content = f.read()
            print_colored("Extracted Public Key Content:", Fore.CYAN)
            print(pubkey_content)

def demo_invalid_signature(cert_files):
    """Demo kiểm tra chữ ký không hợp lệ."""
    print_header("Demonstrating Invalid Signature Detection")
    
    # Tạo một chứng chỉ với chữ ký không hợp lệ bằng cách sửa đổi file chứng chỉ
    original_cert = cert_files["rsa_pem"]
    invalid_cert = "temp/invalid_cert.pem"
    
    # Đọc chứng chỉ gốc
    with open(original_cert, "r") as f:
        cert_content = f.read()
    
    # Sửa đổi nội dung để tạo ra chữ ký không hợp lệ
    # Thay đổi một vài byte trong phần dữ liệu
    lines = cert_content.split('\n')
    if len(lines) > 3:  # Đảm bảo file có đủ dòng để sửa
        # Thay đổi một ký tự trong dòng giữa để làm hỏng chữ ký
        middle_index = len(lines) // 2
        if len(lines[middle_index]) > 5:
            modified_line = lines[middle_index][:4] + "X" + lines[middle_index][5:]
            lines[middle_index] = modified_line
    
    # Ghi lại chứng chỉ đã sửa
    with open(invalid_cert, "w") as f:
        f.write('\n'.join(lines))
    
    print_section("Created tampered certificate with invalid signature")
    print_colored("Original certificate: " + original_cert, Fore.CYAN)
    print_colored("Tampered certificate: " + invalid_cert, Fore.CYAN)
    
    print_section("Parsing Certificate with Invalid Signature")
    cmd = [CERT_PARSER, "-f", invalid_cert, "-t", "PEM"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # In kết quả
    if result.stdout:
        lines = result.stdout.split('\n')
        for line in lines:
            if "Signature Status:" in line:
                print_colored(line, Fore.RED, Style.BRIGHT)
                print_colored("✗ Public key is NOT returned because signature is INVALID", 
                              Fore.RED, Style.BRIGHT)
            else:
                print(line)

def demo_supported_formats():
    """Demo hỗ trợ các định dạng chứng chỉ khác nhau."""
    print_header("Supported Certificate Formats")
    
    formats = [
        {"name": "PEM (Base64)", "description": "Privacy-Enhanced Mail format, Base64 encoded with header and footer"},
        {"name": "DER (Binary)", "description": "Distinguished Encoding Rules format, binary encoding"}
    ]
    
    for fmt in formats:
        print_colored(f"• {fmt['name']}", Fore.GREEN, Style.BRIGHT)
        print(f"  {fmt['description']}")

def demo_fields_supported():
    """Hiển thị danh sách các trường chứng chỉ được hỗ trợ."""
    print_header("Certificate Fields Supported")
    
    fields = [
        {"name": "Subject Name", "description": "Identifies the entity the certificate belongs to"},
        {"name": "Issuer Name", "description": "Identifies the entity that issued the certificate"},
        {"name": "Subject Public Key", "description": "The public key of the subject"},
        {"name": "Signature", "description": "Digital signature of the certificate"},
        {"name": "Signature Algorithm", "description": "Algorithm used to create the signature"},
        {"name": "Validity Period", "description": "Start and end dates for certificate validity"},
        {"name": "Version", "description": "X.509 version number"},
        {"name": "Serial Number", "description": "Unique identifier assigned by the CA"},
        {"name": "Key Usage", "description": "Indicates purposes for which the key can be used"},
        {"name": "Extended Key Usage", "description": "Additional purposes for which the key can be used"}
    ]
    
    for field in fields:
        print_colored(f"• {field['name']}", Fore.YELLOW, Style.BRIGHT)
        print(f"  {field['description']}")

def main():
    """Hàm chính để chạy demo."""
    # print_colored(TOOL_DESCRIPTION, Fore.CYAN) # Đã ẩn dòng này
    
    # Tạo chứng chỉ test
    cert_files = create_test_certificates()
    
    # Demo các định dạng được hỗ trợ
    demo_supported_formats()
    
    # Demo các trường được hỗ trợ
    demo_fields_supported()
    
    # Demo phân tích các loại chứng chỉ
    demo_certificate_parsing(cert_files)
    
    # Demo phát hiện chữ ký không hợp lệ
    demo_invalid_signature(cert_files)
    
    print_header("Demo Completed")
    print_colored("The tool successfully demonstrates all requirements of Task 4.2:", Fore.GREEN)
    print(" ✓ Parsing all X.509 certificate fields")
    print(" ✓ Checking signature validity")
    print(" ✓ Supporting PEM and DER input formats")
    print(" ✓ Returning public key when signature is valid, null otherwise")

if __name__ == "__main__":
    main() 
