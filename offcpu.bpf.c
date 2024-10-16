#include <stdint.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef uint64_t u64;
struct __attribute__((visibility("default"))) trace_event_raw_sched_switch {
    // Struct
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 64);
} offcpu_histogram SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 key = bpf_ktime_get_ns() / 1000000;  // Time in milliseconds
    u64 *value = bpf_map_lookup_elem(&offcpu_histogram, &key);

    if (value) {
        (*value)++;
    } else {
        u64 init_count = 1;
        bpf_map_update_elem(&offcpu_histogram, &key, &init_count, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
