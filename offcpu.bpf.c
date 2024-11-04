#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_RUNNING 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} offcpu_histogram SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} start_time SEC(".maps");

static int trace_sched_switch(struct task_struct *prev, struct task_struct *next) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = BPF_CORE_READ(prev, pid);
    u32 next_pid = BPF_CORE_READ(next, pid);
    u64 *start_ts, delta;

    long prev_state = BPF_CORE_READ(prev, __state);
    if (prev_state == TASK_RUNNING) {
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    start_ts = bpf_map_lookup_elem(&start_time, &next_pid);
    if (start_ts) {
        delta = ts - *start_ts;
        u64 key = delta / 1000;

        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &key);
        if (count) {
            (*count)++;
        } else {
            u64 init_val = 1;
            bpf_map_update_elem(&offcpu_histogram, &key, &init_val, BPF_ANY);
        }

        bpf_map_delete_elem(&start_time, &next_pid);
    }

    return 0;
}

// Use the standard tracepoint for sched_switch
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    struct task_struct *prev = (struct task_struct *)ctx->prev;
    struct task_struct *next = (struct task_struct *)ctx->next;
    return trace_sched_switch(prev, next);
}

char LICENSE[] SEC("license") = "GPL";


// SEC("raw_tp/sched_switch")
// int BPF_PROG(handle_sched_switch, struct task_struct *prev, struct task_struct *next){
//     return trace_sched_switch(prev, next);
// }

