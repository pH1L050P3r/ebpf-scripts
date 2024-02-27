#!/usr/bin/python3
from bcc import BPF
from time import sleep
import signal

CFLAGS = ["-Wno-macro-redefined"]


PROG = """
#include <uapi/linux/ptrace.h>
struct key {
    u32 pid;
    u32 cpu;
    u64 time;
};
BPF_HASH(start, u32);
BPF_PERF_OUTPUT(output);

int on_sched_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 start_time = bpf_ktime_get_ns();
    start.update(&cpu, &start_time);
    return 0;
}
 
int on_sched_switch_return(struct pt_regs *ctx, struct task_struct *prev){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 cpu = bpf_get_smp_processor_id();
    
    u64 *timestamp, start_time, delta;
    timestamp = start.lookup(&cpu);

    if(timestamp != NULL){
        delta = bpf_ktime_get_ns() - *timestamp;
        struct key k = { .pid = pid, .cpu = cpu, .time = delta};
        output.perf_submit(ctx, &k, sizeof(k));
    }
    return 0;
}
 
 
"""
# Load BPF program
b = BPF(text=PROG, cflags=CFLAGS)
b.attach_kprobe(event="schedule", fn_name="on_sched_switch")
b.attach_kretprobe(event="schedule", fn_name="on_sched_switch_return")
context_switch_data = []


def signal_handler(signal, frame):
    b.perf_buffer_poll()
    print('\033c', end="")

    if(len(context_switch_data) <= 0):
        print("No context switches measured.")
        exit(0)

    min_time =  min(map(lambda x : x[2], context_switch_data))
    max_time =  max(map(lambda x : x[2], context_switch_data))
    mean_time = sum(map(lambda x : x[2], context_switch_data)) // len(context_switch_data)

    print(f"Min time: {min_time} ns")
    print(f"Max time: {max_time} ns")
    print(f"Mean time: {mean_time} ns")
    exit(0)
        
    


# Attach signal handler
signal.signal(signal.SIGINT, signal_handler)
def event_add_data_to_context_switch_list(cpu, data, size):
    data = b["output"].event(data)
    context_switch_data.append([data.pid, data.cpu, data.time])

b["output"].open_perf_buffer(event_add_data_to_context_switch_list)
while True:
    sleep(10)
    b.perf_buffer_poll()