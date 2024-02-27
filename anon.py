#!/usr/bin/python
from bcc import BPF
from time import sleep

CFLAGS = ["-Wno-macro-redefined"]

# Define the BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>

BPF_HASH(allocations, u32);

TRACEPOINT_PROBE(syscalls, sys_enter_mmap)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 size = args->len;
    if(args->flags & MAP_ANONYMOUS)
        // allocations.increment(pid, ((size + 4095) / 4096) * 4096);
        allocations.increment(pid, size);
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_program, cflags=CFLAGS)
b.attach_tracepoint("syscalls:sys_enter_mmap", "tracepoint__syscalls__sys_enter_mmap")


i = None

while True:
    if(i is None):
        i = int(input("Enter PID : "))
    s = ""
    for k, v in b["allocations"].items():
        if k.value == i:
            s += f"ID {k.value}: {v.value}\n"
    # print('\033c', end="")
    print(s, end="", flush=True)
