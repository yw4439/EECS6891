#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <getopt.h>

void print_histogram(int map_fd, const char *label) {
    unsigned long key = 0, next_key, count;
    printf("\n%s:\n", label);
    printf("usecs : count\n");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &count) == 0) {
            printf("%8lu -> %8lu : %lu |%.*s\n", next_key, next_key * 2 - 1, count,
                   (int)(count / 2), "****************************************");
        }
        key = next_key;
    }
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog_sched_switch, *prog_sched_wakeup;
    struct bpf_link *link_sched_switch, *link_sched_wakeup;
    int offcpu_fd, blocked_fd;

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

    // Find the BPF program for sched_switch by its name
    prog_sched_switch = bpf_object__find_program_by_name(obj, "handle_sched_switch");
    if (!prog_sched_switch) {
        fprintf(stderr, "Failed to find handle_sched_switch program\n");
        return 1;
    }

    // Attach the BPF program to the sched:sched_switch tracepoint
    link_sched_switch = bpf_program__attach_tracepoint(prog_sched_switch, "sched", "sched_switch");
    if (!link_sched_switch) {
        fprintf(stderr, "Failed to attach handle_sched_switch program\n");
        return 1;
    }

    // Find the BPF program for sched_wakeup by its name
    prog_sched_wakeup = bpf_object__find_program_by_name(obj, "handle_sched_wakeup");
    if (!prog_sched_wakeup) {
        fprintf(stderr, "Failed to find handle_sched_wakeup program\n");
        bpf_link__destroy(link_sched_switch);
        return 1;
    }

    // Attach the BPF program to the sched:sched_wakeup tracepoint
    link_sched_wakeup = bpf_program__attach_tracepoint(prog_sched_wakeup, "sched", "sched_wakeup");
    if (!link_sched_wakeup) {
        fprintf(stderr, "Failed to attach handle_sched_wakeup program\n");
        bpf_link__destroy(link_sched_switch);
        return 1;
    }

    // Find histogram maps by name
    offcpu_fd = bpf_object__find_map_fd_by_name(obj, "offcpu_histogram");
    blocked_fd = bpf_object__find_map_fd_by_name(obj, "blocked_histogram");
    if (offcpu_fd < 0 || blocked_fd < 0) {
        fprintf(stderr, "Failed to find BPF maps: %s\n", strerror(errno));
        bpf_link__destroy(link_sched_switch);
        bpf_link__destroy(link_sched_wakeup);
        return 1;
    }

    printf("BPF program successfully loaded and attached!\n");

    // Periodically print the histograms
    while (1) {
        print_histogram(offcpu_fd, "Off-CPU Time Histogram");
        print_histogram(blocked_fd, "Blocked Time Histogram");
        sleep(5);
    }

    // Cleanup
    bpf_link__destroy(link_sched_switch);
    bpf_link__destroy(link_sched_wakeup);
    bpf_object__close(obj);
    return 0;
}