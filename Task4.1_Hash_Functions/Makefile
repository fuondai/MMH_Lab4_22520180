CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2

# Phát hiện OS
ifeq ($(OS),Windows_NT)
    # Cấu hình Windows 
    INCLUDE_DIR = ./include
    LIB_DIR = ./lib
    LDFLAGS = -I$(INCLUDE_DIR) -I"C:/Program Files/OpenSSL-Win64/include" -L$(LIB_DIR) -L"C:/Program Files/OpenSSL-Win64/lib" -lcryptopp -lcrypto
    EXECUTABLE = hash_functions.exe
else
    # Cấu hình Linux 
    INCLUDE_DIR = ./include
    LIB_DIR = ./lib
    LDFLAGS = -I$(INCLUDE_DIR) -L$(LIB_DIR) -lcryptopp -lcrypto
    EXECUTABLE = hash_functions
endif

TARGET = $(EXECUTABLE)
SRC = hash_functions.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
