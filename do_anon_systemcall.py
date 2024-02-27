#!/usr/bin/python
from bcc import BPF
from time import sleep

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

BPF_HASH(process_page_count, u64, u64);

int trace_do_anonymous_page(struct pt_regs *ctx) {
    struct vm_area_struct *vma = (struct vm_area_struct *)PT_REGS_PARM1(ctx);
    u64 page_addr = (u64)vma->vm_start;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0;

    u64 *count = process_page_count.lookup(&pid);
    if (count == NULL) {
        process_page_count.update(&pid, &zero);
    } else {
        (*count)++;
    }

    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="do_anonymous_page", fn_name="trace_do_anonymous_page")

# Print information about anonymous memory usage by process
try:
    id_ = None
    id_ = int(input("Enter Id : "))
    s = "%-6s %-6s %-6s\n" % ("PID", "ANON_PAGES", "KB")
    while True:
        sleep(1)
        # s = "%-6s %-6s %-6s\n" % ("PID", "ANON_PAGES", "KB")
        for key, value in b["process_page_count"].items():
            if(id_ and key.value == id_):
                s += "%-6d %-6d %-6d\n" % (key.value, value.value, value.value * 4)
        print('\033c', end="")
        print(s)
except KeyboardInterrupt:
    pass
