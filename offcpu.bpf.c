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
    __type(key, u64);
    __type(value, u64);
} blocked_histogram SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} start_times SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;
    long prev_state = ctx->prev_state;

    if (prev_state == TASK_RUNNING) {
        // Store the timestamp for the previous task
        bpf_map_update_elem(&start_times, &prev_pid, &ts, BPF_ANY);
    }

    // Calculate off-CPU time for the next task
    u64 *start_ts = bpf_map_lookup_elem(&start_times, &next_pid);
    if (start_ts) {
        u64 delta = ts - *start_ts;  // Calculate off-CPU time in nanoseconds
        u64 bucket = delta / 1000;   // Convert to microseconds

        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &bucket);
        if (count) {
            (*count)++;
        } else {
            u64 initial_count = 1;
            bpf_map_update_elem(&offcpu_histogram, &bucket, &initial_count, BPF_ANY);
        }
        bpf_map_delete_elem(&start_times, &next_pid);
    }

    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(void *ctx) {
    u32 pid;
    u64 ts = bpf_ktime_get_ns();

    // Directly read the pid field from the context assuming it's at the start of ctx
    bpf_probe_read_kernel(&pid, sizeof(pid), ctx);

    // Rest of the code remains the same
    u64 *start_ts = bpf_map_lookup_elem(&start_times, &pid);
    if (start_ts) {
        u64 delta = ts - *start_ts;  // Blocked time in nanoseconds
        u64 bucket = delta / 1000;   // Convert to microseconds

        u64 *count = bpf_map_lookup_elem(&blocked_histogram, &bucket);
        if (count) {
            (*count)++;
        } else {
            u64 initial_count = 1;
            bpf_map_update_elem(&blocked_histogram, &bucket, &initial_count, BPF_ANY);
        }
        bpf_map_delete_elem(&start_times, &pid);
    }

    // Store the wakeup time for the next time it switches off CPU
    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";



// SEC("raw_tp/sched_switch")
// int BPF_PROG(handle_sched_switch, struct task_struct *prev, struct task_struct *next){
//     return trace_sched_switch(prev, next);
// }

