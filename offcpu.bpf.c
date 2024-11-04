#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Define constants
#define MAX_ENTRIES 10240
#define TASK_RUNNING 0

// Histogram map to store off-CPU times
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);         // Key is the off-CPU time (in microseconds)
    __type(value, u64);       // Value is the count (frequency of occurrence)
} offcpu_histogram SEC(".maps");

// Map to store the start times (in nanoseconds) for tasks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);         // Key is the PID (process ID)
    __type(value, u64);       // Value is the timestamp in nanoseconds
} start_time SEC(".maps");

// Function to handle the sched_switch event
static int trace_sched_switch(struct task_struct *prev, struct task_struct *next) {
    u64 ts = bpf_ktime_get_ns();  // Get current timestamp in nanoseconds
    u32 prev_pid = BPF_CORE_READ(prev, pid);  // Get PID of the previous task
    u32 next_pid = BPF_CORE_READ(next, pid);  // Get PID of the next task
    u64 *start_ts, delta;
    
    // New method: Get the state of the previous task using task_state in newer kernels
    long prev_state = BPF_CORE_READ(prev, __state);

    // If the previous task was running, record its start time
    if (prev_state == TASK_RUNNING) {
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);  // Store start time
    }

    // Check if the next task's start time is stored
    start_ts = bpf_map_lookup_elem(&start_time, &next_pid);
    if (start_ts) {
        delta = ts - *start_ts;  // Calculate off-CPU time (in nanoseconds)

        // Convert the time from nanoseconds to microseconds
        u64 key = delta / 1000;

        // Look up the corresponding histogram bucket
        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &key);
        if (count) {
            (*count)++;  // Increment the bucket count if it exists
        } else {
            u64 init_val = 1;
            bpf_map_update_elem(&offcpu_histogram, &key, &init_val, BPF_ANY);  // Create a new bucket
        }

        // Clean up: remove the start time after use
        bpf_map_delete_elem(&start_time, &next_pid);
    }

    return 0;
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, struct task_struct *prev, struct task_struct *next){
    return trace_sched_switch(prev, next);
}

// // Attach to the sched_switch tracepoint
// SEC("tracepoint/sched/sched_switch")
// int handle_sched_switch(struct task_struct *prev, struct task_struct *next) {
//     return trace_sched_switch(prev, next);
// }

// License for the eBPF program
char LICENSE[] SEC("license") = "GPL";