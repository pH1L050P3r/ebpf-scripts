from bcc import BPF
CFLAGS = ["-Wno-macro-redefined"]

# BPF program to trace sched_switch events
bpf_program = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 prev_pid;
};

BPF_HASH(last_switch, struct key_t, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    struct key_t key = {};
    key.prev_pid = args->prev_pid;

    u64 *ts = last_switch.lookup(&key);
    if (ts) {
        // Print the time difference since the last context switch
        bpf_trace_printk("PID %d switched out by PID %d at %llu us\\n", key.prev_pid, args->next_pid, (bpf_ktime_get_ns() - *ts) / 1000);
    }

    // Update the timestamp for the current process
    u64 now = bpf_ktime_get_ns();
    last_switch.update(&key, &now);

    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program, cflags=CFLAGS)

b.attach_tracepoint("sched:sched_switch", "tracepoint__sched__sched_switch")

# Print output
b.trace_print()
