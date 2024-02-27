#!/usr/bin/python
from bcc import BPF

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

BPF_HASH(process_page_count, u32, u64);

int trace_do_anonymous_page(struct pt_regs *ctx) {
    struct vm_area_struct *vma = (struct vm_area_struct *)PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Count pages by iterating over the page tables
    u64 num_pages = 0;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(vma->vm_mm, vma->vm_start);
    pud = pud_offset(pgd, vma->vm_start);
    pmd = pmd_offset(pud, vma->vm_start);
    pte = pte_offset_map(pmd, vma->vm_start);

    do {
        num_pages++;
    } while (pte++, pte++, pte++, pte++, pte++, pte++, pte++, pte++, pte++, pte++, pte++, pte++);

    u64 *count = process_page_count.lookup(&pid);
    if (count == NULL) {
        process_page_count.update(&pid, &num_pages);
    } else {
        (*count) += num_pages;
    }

    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="do_anonymous_page", fn_name="trace_do_anonymous_page")

# Print information about anonymous memory usage by process in KB
try:
    print("%-6s %-15s" % ("PID", "ANON_PAGES(KB)"))
    while True:
        count = b["process_page_count"].items()
        for key, value in count:
            # Assuming page size is 4 KB
            kb_usage = value.value * 4
            print("%-6d %-15d" % (key.value, kb_usage))
except KeyboardInterrupt:
    pass
