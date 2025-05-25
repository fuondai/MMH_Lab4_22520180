CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
LDFLAGS = -lcrypto -lssl

TARGET = certificate_attack
SRC = certificate_attack.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
