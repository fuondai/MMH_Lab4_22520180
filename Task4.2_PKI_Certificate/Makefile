CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2

# Phát hiện hệ điều hành
ifeq ($(OS),Windows_NT)
    # Cấu hình cho Windows
    EXECUTABLE = certificate_parser.exe
    # Đường dẫn OpenSSL cho Windows - có thể cần điều chỉnh theo môi trường cài đặt
    OPENSSL_DIR = "C:/Program Files/OpenSSL-Win64"
    INCLUDE_DIR = $(OPENSSL_DIR)/include
    LIB_DIR = $(OPENSSL_DIR)/lib
    # Thêm định nghĩa _WIN32 để kích hoạt mã xử lý OPENSSL_Applink
    CXXFLAGS += -D_WIN32
    LDFLAGS = -I$(INCLUDE_DIR) -L$(LIB_DIR) -lssl -lcrypto -lws2_32 -lcrypt32 -lgdi32
    RM_CMD = del /Q
else
    # Cấu hình cho Linux/Unix
    EXECUTABLE = certificate_parser
    LDFLAGS = -lssl -lcrypto
    RM_CMD = rm -f
endif

TARGET = $(EXECUTABLE)
SRC = certificate_parser.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM_CMD) $(TARGET)

.PHONY: all clean
