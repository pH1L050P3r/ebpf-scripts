#!/usr/bin/python
from bcc import BPF
from time import sleep

CFLAGS = ["-Wno-macro-redefined"]

# Define the BPF program
bpf_program = """
#include <linux/sched.h>
#include <linux/mm_types.h>

BPF_HASH(allocations, u64, u64);

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = bpf_get_current_pid_tgid() >> 32;

    if (task->mm && task->mm->hiwater_vm > 0) {
        u64 size = task->mm->hiwater_vm * PAGE_SIZE;
        allocations.update(&pid, &size);
    }

    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_program, cflags=CFLAGS)
b.attach_tracepoint("kmem:mm_page_alloc", "tracepoint__kmem__mm_page_alloc")

i = None

while True:
    if(i is None):
        i = int(input("Enter PID : "))
    s = ""
    for k, v in b["allocations"].items():
        if k.value == i:
            s += f"ID {k.value}: {v.value / 1024} KB\n"
    print('\033c', end="")
    print(s, end="", flush=True)