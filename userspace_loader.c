#include <bpf/libbpf.h>
#include <bpf/bpf.h> 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#define MAX_BUCKETS 64

typedef uint64_t u64;

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --time_interval <value> [--pid <value>]\n", prog);
    exit(1);
}

void print_histogram(int map_fd) {
    u64 key = 0, next_key;
    u64 value;

    printf("Histogram data:\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("Key: %llu, Value: %llu\n", next_key, value);
        }
        key = next_key;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
    }

    const char *bpf_prog_file = "offcpu.bpf.o";
    struct bpf_object *obj;
    int map_fd;
    int err;

    // Open the BPF object file.
    obj = bpf_object__open_file(bpf_prog_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    // Load the BPF program into the kernel.
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        return 1;
    }

    printf("BPF program loaded successfully!\n");

    // Retrieve the file descriptor of the histogram map.
    map_fd = bpf_object__find_map_fd_by_name(obj, "offcpu_histogram");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map: %s\n", strerror(errno));
        return 1;
    }

    // Print the histogram data.
    print_histogram(map_fd);

    bpf_object__close(obj);

    return 0;
}
