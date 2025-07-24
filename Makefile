CC = clang
CFLAGS = -O2 -g -Wall -Wextra
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_arm64 -D__BPF_TRACING__
INCLUDES = -I/usr/include -I/usr/include/aarch64-linux-gnu -Isrc -I/usr/include/arm-linux-gnueabihf
LIBS = -lbpf -lssl -lcrypto -lpthread

# Source files
BPF_SRC = src/tls_capture.bpf.c
BPF_COMPLETE_SRC = src/complete_tls_capture.bpf.c
USER_SRC = src/tls_capture.c src/ssl_hooks.c src/crypto_utils.c src/packet_parser.c
HEADERS = src/tls_capture.h src/common.h src/simple_bpf_types.h

# Output files
BPF_OBJ = tls_capture.bpf.o
BPF_COMPLETE_OBJ = complete_tls_capture.bpf.o
TARGET = tls_capture

.PHONY: all clean install

all: $(TARGET) $(BPF_OBJ) $(BPF_COMPLETE_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(HEADERS)
	$(CC) $(BPF_CFLAGS) $(INCLUDES) -c $(BPF_SRC) -o $(BPF_OBJ)

$(BPF_COMPLETE_OBJ): $(BPF_COMPLETE_SRC) $(HEADERS)
	$(CC) $(BPF_CFLAGS) $(INCLUDES) -c $(BPF_COMPLETE_SRC) -o $(BPF_COMPLETE_OBJ)

$(TARGET): $(BPF_OBJ) $(USER_SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) $(USER_SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(BPF_OBJ) $(BPF_COMPLETE_OBJ) $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo cp $(BPF_OBJ) /usr/local/share/

check-deps:
	@echo "Checking dependencies..."
	@which clang > /dev/null || (echo "clang not found" && exit 1)
	@test -f /usr/include/bpf/libbpf.h || (echo "libbpf headers not found" && exit 1)
	@test -f /usr/include/openssl/ssl.h || (echo "openssl headers not found" && exit 1)
	@test -f /usr/lib/*/libbpf.so || test -f /usr/lib64/libbpf.so || (echo "libbpf library not found" && exit 1)
	@test -f /usr/lib/*/libssl.so || test -f /usr/lib64/libssl.so || (echo "openssl library not found" && exit 1)
	@echo "All dependencies found"
