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

static int trace_sched_switch(u32 prev_pid, u32 next_pid, long prev_state) {
    u64 ts = bpf_ktime_get_ns();
    u64 *start_ts, delta;

    // If the previous task was running, record its start time
    if (prev_state == TASK_RUNNING) {
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    // Check if the next task's start time is stored
    start_ts = bpf_map_lookup_elem(&start_time, &next_pid);
    if (start_ts) {
        delta = ts - *start_ts;
        u64 key = delta / 1000;  // Convert to microseconds

        // Look up the corresponding histogram bucket
        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &key);
        if (count) {
            (*count)++;
        } else {
            u64 init_val = 1;
            bpf_map_update_elem(&offcpu_histogram, &key, &init_val, BPF_ANY);
        }

        // Clean up: remove the start time after use
        bpf_map_delete_elem(&start_time, &next_pid);
    }

    return 0;
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u32 prev_pid = ctx->prev_pid;  // Get PID of the previous task
    u32 next_pid = ctx->next_pid;  // Get PID of the next task
    long prev_state = ctx->prev_state;  // Get the state of the previous task

    return trace_sched_switch(prev_pid, next_pid, prev_state);
}

char LICENSE[] SEC("license") = "GPL";



// SEC("raw_tp/sched_switch")
// int BPF_PROG(handle_sched_switch, struct task_struct *prev, struct task_struct *next){
//     return trace_sched_switch(prev, next);
// }

