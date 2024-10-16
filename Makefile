CC = clang
CFLAGS = -O2 -g -Wall -target bpf \
    -I/usr/include \
    -I/usr/include/asm \
    -I/usr/include/i386-linux-gnu \
    -I/usr/include/x86_64-linux-gnu \
    -I/usr/src/linux-headers-$(uname -r)/include \
    -I/usr/src/linux-headers-$(uname -r)/arch/x86/include \
    -I/usr/src/linux-headers-$(uname -r)/arch/x86/include/uapi \
    -I/usr/src/linux-headers-$(uname -r)/include/uapi \
    -I/usr/src/linux-headers-$(uname -r)/arch/x86/include/generated/uapi \
    -I/usr/src/linux-headers-$(uname -r)/include/generated/uapi \
    -I/usr/lib/llvm-14/include
BPF_PROG = offcpu.bpf.o
LOADER = userspace_loader

all: $(BPF_PROG) $(LOADER)

$(BPF_PROG): offcpu.bpf.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LOADER): userspace_loader.c
	gcc -o $@ $< -lbpf -lelf

clean:
	rm -f $(BPF_PROG) $(LOADER)
