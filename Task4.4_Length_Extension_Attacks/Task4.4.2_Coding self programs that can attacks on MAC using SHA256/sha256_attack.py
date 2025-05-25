import struct
import io
import hashlib 

# Hằng số SHA-256
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def _rotr(n, b):
    return ((n >> b) | (n << (32 - b))) & 0xffffffff

def _shr(n, b):
    return (n >> b) & 0xffffffff

def _sigma0(n):
    return _rotr(n, 2) ^ _rotr(n, 13) ^ _rotr(n, 22)

def _sigma1(n):
    return _rotr(n, 6) ^ _rotr(n, 11) ^ _rotr(n, 25)

def _gamma0(n):
    return _rotr(n, 7) ^ _rotr(n, 18) ^ _shr(n, 3)

def _gamma1(n):
    return _rotr(n, 17) ^ _rotr(n, 19) ^ _shr(n, 10)

def _ch(x, y, z):
    return (x & y) ^ (~x & z)

def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sha256_padding(message_len_bytes):
    """
    Tính toán phần đệm SHA-256 cho một thông điệp có độ dài cho trước.

    Args:
        message_len_bytes: Độ dài của thông điệp gốc tính bằng byte.

    Returns:
        bytes: Các byte đệm.
    """
    message_len_bits = message_len_bytes * 8
    padding = b'\x80'
    # Tính số byte 0 cần thiết
    # Tổng độ dài cần phải đồng dư với 56 (mod 64) byte, hoặc 448 (mod 512) bit
    padding_len = (56 - (message_len_bytes + 1) % 64) % 64
    padding += b'\x00' * padding_len
    # Nối độ dài gốc dưới dạng số nguyên 64-bit big-endian
    padding += struct.pack('>Q', message_len_bits)
    return padding

class Sha256:
    """Triển khai SHA-256 bằng Python thuần túy, được điều chỉnh cho tấn công mở rộng độ dài."""
    name = 'sha256'
    digest_size = 32
    block_size = 64

    def __init__(self, initial_state=None, processed_len_bits=0):
        self._buffer = b''
        # QUAN TRỌNG: _len theo dõi tổng số bit đã được xử lý *trước khi* instance này bắt đầu,
        # cộng với số bit được thêm vào thông qua các lệnh gọi update() đến instance này.
        self._len = processed_len_bits

        if initial_state:
            if len(initial_state) != 8:
                raise ValueError("Trạng thái ban đầu phải chứa 8 số nguyên 32-bit")
            self._h = list(initial_state)
        else:
            # Giá trị hash ban đầu tiêu chuẩn nếu không có trạng thái nào được cung cấp
            self._h = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ]

    def _process_chunk(self, chunk):
        if len(chunk) != 64:
            # Điều này không nên xảy ra với logic đệm chính xác
            raise ValueError(f"Chunk phải là 64 byte, nhận được {len(chunk)}")

        w = [0] * 64
        for i in range(16):
            w[i] = struct.unpack('>I', chunk[i*4:i*4+4])[0]

        for i in range(16, 64):
            s0 = _gamma0(w[i-15])
            s1 = _gamma1(w[i-2])
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = self._h

        for i in range(64):
            s1 = _sigma1(e)
            ch = _ch(e, f, g)
            temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff
            s0 = _sigma0(a)
            maj = _maj(a, b, c)
            temp2 = (s0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        self._h[0] = (self._h[0] + a) & 0xffffffff
        self._h[1] = (self._h[1] + b) & 0xffffffff
        self._h[2] = (self._h[2] + c) & 0xffffffff
        self._h[3] = (self._h[3] + d) & 0xffffffff
        self._h[4] = (self._h[4] + e) & 0xffffffff
        self._h[5] = (self._h[5] + f) & 0xffffffff
        self._h[6] = (self._h[6] + g) & 0xffffffff
        self._h[7] = (self._h[7] + h) & 0xffffffff

    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8') # Giả sử utf-8 nếu là chuỗi
        self._buffer += data
        # Cập nhật tổng độ dài đã xử lý *bởi instance này* và *trước đó*
        self._len += len(data) * 8

        # Xử lý các khối đầy đủ
        while len(self._buffer) >= 64:
            chunk = self._buffer[:64]
            self._buffer = self._buffer[64:]
            self._process_chunk(chunk)

    def digest(self):
        # Tạo một bản sao của trạng thái hiện tại để hoàn tất
        h_final = list(self._h)
        buffer_final = self._buffer
        len_final = self._len

        # --- Đệm để hoàn tất ---
        # Nối bit '1'
        buffer_final += b'\x80'

        # Nối K bit '0', trong đó K là số nhỏ nhất >= 0 sao cho L + 1 + K + 64 là bội số của 512
        # Hoặc tính bằng byte: len(buffer_final) cần là 56 (mod 64)
        padding_zeros_len = (56 - len(buffer_final) % 64) % 64
        buffer_final += b'\x00' * padding_zeros_len

        # Nối độ dài của thông điệp gốc (tổng độ dài được theo dõi) tính bằng bit dưới dạng số nguyên 64-bit big-endian
        buffer_final += struct.pack('>Q', len_final)
        # --- Kết thúc đệm ---

        # Xử lý (các) khối đệm cuối cùng bằng cách sử dụng trạng thái đã sao chép
        temp_h = list(h_final) # Làm việc trên một bản sao để xử lý các khối cuối cùng
        while len(buffer_final) >= 64:
            chunk = buffer_final[:64]
            buffer_final = buffer_final[64:]

            # --- Logic xử lý chunk (sao chép từ _process_chunk cho rõ ràng) ---
            w = [0] * 64
            for i in range(16):
                w[i] = struct.unpack('>I', chunk[i*4:i*4+4])[0]
            for i in range(16, 64):
                s0 = _gamma0(w[i-15])
                s1 = _gamma1(w[i-2])
                w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
            a, b, c, d, e, f, g, h = temp_h
            for i in range(64):
                s1 = _sigma1(e)
                ch = _ch(e, f, g)
                temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff
                s0 = _sigma0(a)
                maj = _maj(a, b, c)
                temp2 = (s0 + maj) & 0xffffffff
                h = g; g = f; f = e; e = (d + temp1) & 0xffffffff;
                d = c; c = b; b = a; a = (temp1 + temp2) & 0xffffffff
            temp_h[0] = (temp_h[0] + a) & 0xffffffff
            temp_h[1] = (temp_h[1] + b) & 0xffffffff
            temp_h[2] = (temp_h[2] + c) & 0xffffffff
            temp_h[3] = (temp_h[3] + d) & 0xffffffff
            temp_h[4] = (temp_h[4] + e) & 0xffffffff
            temp_h[5] = (temp_h[5] + f) & 0xffffffff
            temp_h[6] = (temp_h[6] + g) & 0xffffffff
            temp_h[7] = (temp_h[7] + h) & 0xffffffff
            # --- Kết thúc logic xử lý chunk ---

        # Hash cuối cùng nằm trong temp_h
        return b''.join(struct.pack('>I', val) for val in temp_h)

    def hexdigest(self):
        return self.digest().hex()

# --- Hàm tấn công mở rộng độ dài ---

def sha256_length_extension(original_digest_hex, key_len_bytes, original_message, extension_string):
    """
    Thực hiện tấn công mở rộng độ dài SHA-256.

    Args:
        original_digest_hex (str): Chuỗi hex digest của SHA256(key || original_message).
        key_len_bytes (int): Độ dài của khóa bí mật tính bằng byte.
        original_message (bytes): Dữ liệu thông điệp gốc.
        extension_string (bytes): Chuỗi cần nối thêm.

    Returns:
        tuple: (new_digest_hex, forged_message_part)
               new_digest_hex: Chuỗi hex digest của SHA256(key || original_message || padding || extension_string).
               forged_message_part: Phần thông điệp giả mạo (original_message || padding || extension_string)
                                    mà khi được nối với khóa gốc sẽ cho ra digest mới.
    """
    if len(original_digest_hex) != 64:
        raise ValueError("Digest gốc phải là một chuỗi hex 64 ký tự (SHA-256)")
    if not isinstance(original_message, bytes):
        raise TypeError("Thông điệp gốc phải là bytes")
    if not isinstance(extension_string, bytes):
        raise TypeError("Chuỗi mở rộng phải là bytes")
    if not isinstance(key_len_bytes, int) or key_len_bytes < 0:
        raise ValueError("Độ dài khóa phải là một số nguyên không âm")


    # 1. Tính toán độ dài của dữ liệu được hash ban đầu (key + message)
    original_data_len_bytes = key_len_bytes + len(original_message)

    # 2. Tính toán phần đệm *sẽ* được áp dụng cho (key + message)
    # Phần đệm này là một phần của thông điệp giả mạo mà kẻ tấn công gửi.
    padding = sha256_padding(original_data_len_bytes)

    # 3. Xây dựng phần thông điệp mà kẻ tấn công gửi/sử dụng
    # (original_message || padding || extension_string)
    forged_message_part = original_message + padding + extension_string

    # 4. Phân tích digest gốc thành trạng thái ban đầu (h0-h7) cho phần mở rộng
    initial_state = []
    for i in range(0, 64, 8):
        # Chuyển đổi các cặp hex thành byte, sau đó giải nén dưới dạng số nguyên không dấu big-endian
        initial_state.append(struct.unpack('>I', bytes.fromhex(original_digest_hex[i:i+8]))[0])

    # 5. Tính toán tổng độ dài đã được xử lý bởi hash gốc, *bao gồm cả phần đệm*.
    # Độ dài này cần thiết để khởi tạo chính xác trạng thái SHA-256 cho phần mở rộng.
    # Độ dài là (key_len + original_message_len + padding_len) byte.
    # Nó phải là bội số của kích thước khối (64 byte).
    original_padded_len_bytes = original_data_len_bytes + len(padding)
    if original_padded_len_bytes % 64 != 0:
         # Điều này cho thấy lỗi trong tính toán đệm hoặc hiểu sai
         raise Exception(f"Lỗi nội bộ: Độ dài đã đệm ({original_padded_len_bytes}) không phải là bội số của 64")
    original_padded_len_bits = original_padded_len_bytes * 8

    # 6. Khởi tạo đối tượng Sha256 tùy chỉnh với trạng thái đã bắt và tổng độ dài đã xử lý chính xác
    sha_ext = Sha256(initial_state=initial_state, processed_len_bits=original_padded_len_bits)

    # 7. Cập nhật hash với chuỗi mở rộng. Lớp Sha256 sẽ xử lý
    #    dữ liệu này và áp dụng chính xác phần đệm *cuối cùng* dựa trên
    #    tổng độ dài (thuộc tính _len).
    sha_ext.update(extension_string)

    # 8. Lấy digest mới
    new_digest_hex = sha_ext.hexdigest()

    return new_digest_hex, forged_message_part

# --- Hàm xác minh (để kiểm thử) ---
def verify_attack(key, original_message, extension_string, key_len_bytes, original_digest_hex, calculated_new_digest_hex, forged_message_part):
    """Xác minh kết quả tấn công mở rộng độ dài bằng hashlib."""
    print("\n--- Verification ---")
    print(f"Key: {key.hex()} (Length: {len(key)})")
    print(f"Original Message: {original_message!r}")
    print(f"Extension String: {extension_string!r}")
    print(f"Assumed Key Length: {key_len_bytes}")
    print(f"Original Digest (SHA256(key || msg)): {original_digest_hex}")
    print(f"Forged Message Part (msg || pad || ext): {forged_message_part!r}")
    print(f"Calculated New Digest (Attacker): {calculated_new_digest_hex}")

    # Tính toán phần đệm mà hash gốc sẽ sử dụng
    padding = sha256_padding(key_len_bytes + len(original_message))

    # Xây dựng thông điệp đầy đủ mà máy chủ sẽ hash nếu nhận được forged_message_part
    # Máy chủ nối thêm khóa: key || original_message || padding || extension_string
    full_forged_message = key + original_message + padding + extension_string

    # Đảm bảo forged_message_part khớp với original_message + padding + extension_string
    if forged_message_part != (original_message + padding + extension_string):
        print("ERROR: Forged message part does not match expected structure!")
        print(f"Expected: {(original_message + padding + extension_string)!r}")
        return False

    # Tính toán SHA-256 thực tế của thông điệp giả mạo đầy đủ bằng hashlib tiêu chuẩn
    actual_new_digest = hashlib.sha256(full_forged_message).hexdigest()
    print(f"Actual New Digest (Server - hashlib): {actual_new_digest}")

    if calculated_new_digest_hex == actual_new_digest:
        print("Verification SUCCESSFUL!")
        return True
    else:
        print("Verification FAILED!")
        print(f"Full forged message hashed by server: {full_forged_message!r}")
        return False

# --- Ví dụ sử dụng ---
if __name__ == "__main__":
    # --- Cấu hình ---
    secret_key = b"aaaaaaaaaaaaaaaa" # Thay thế bằng khóa bí mật của bạn
    key_length = len(secret_key) # Kẻ tấn công cần biết hoặc đoán được điều này
    original_msg = b"phuong dai 22520180" # Thông điệp gốc
    extension = b"&admin=true" # Dữ liệu mà kẻ tấn công muốn nối thêm

    print("--- Setup ---")
    print(f"Secret Key (known only to server): {secret_key!r}")
    print(f"Original Message: {original_msg!r}")
    print(f"Desired Extension: {extension!r}")
    print(f"Known Key Length (attacker): {key_length}")

    # --- Phía máy chủ (Mô phỏng) ---
    # Máy chủ tính toán MAC gốc
    original_hasher = hashlib.sha256()
    original_hasher.update(secret_key + original_msg)
    original_mac = original_hasher.hexdigest()
    print(f"Original MAC (generated by server): {original_mac}")

    # --- Phía kẻ tấn công ---
    print("\n--- Attacker Action ---")
    # Kẻ tấn công có: original_mac, key_length, original_msg, extension
    try:
        new_mac, forged_msg_part = sha256_length_extension(
            original_mac,
            key_length,
            original_msg,
            extension
        )
        print(f"Attacker computes Forged Message Part: {forged_msg_part!r}")
        print(f"Attacker computes New MAC: {new_mac}")

        # --- Phía máy chủ (Xác minh) ---
        # Máy chủ nhận forged_msg_part và new_mac từ kẻ tấn công
        # Máy chủ xác minh MAC(key || forged_msg_part) == new_mac
        server_verifier = hashlib.sha256()
        server_verifier.update(secret_key + forged_msg_part)
        server_calculated_mac = server_verifier.hexdigest()

        print("\n--- Server Verification of Attacker's Submission ---")
        print(f"Server computes SHA256(key || forged_msg_part): {server_calculated_mac}")
        if server_calculated_mac == new_mac:
            print("Server accepts the message and MAC! Attack Successful!")
        else:
            print("Server rejects the message and MAC. Attack Failed.")

        # --- Xác minh chi tiết (sử dụng hàm verify_attack) ---
        # Điều này cung cấp các kiểm tra nội bộ chi tiết hơn
        verify_attack(secret_key, original_msg, extension, key_length, original_mac, new_mac, forged_msg_part)

    except Exception as e:
        print(f"An error occurred during the attack: {e}")


