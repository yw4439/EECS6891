#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;

    // Load the BPF object file
    obj = bpf_object__open_file("offcpu.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
        return 1;
    }

    // Load the BPF program into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Get the file descriptor of the loaded BPF program
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "handle_sched_switch"));
    prog = bpf_object__find_program_by_name;
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Attach the BPF program to the sched:sched_switch tracepoint
    if (bpf_program__attach(prog) < 0) {
        fprintf(stderr, "Failed to attach BPF program to tracepoint: %s\n", strerror(errno));
        return 1;
    }

    printf("BPF program successfully loaded and attached!\n");

    // Keep the program running to observe the BPF program's effects
    while (1) {
        sleep(1);
    }

    return 0;
}
