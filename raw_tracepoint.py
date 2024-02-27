from bcc import BPF

CFLAGS = ["-Wno-macro-redefined"]

PROG = r'''
#include <linux/sched.h>

RAW_TRACEPOINT_PROBE(sched_switch)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;

    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);

    bpf_trace_printk("%d -> %ul\n", prev_tgid, prev->last_switch_time);

    return 0;
}
'''

# bpf_trace_printk("%d -> %d\n", prev_tgid, next_tgid);
# TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)


b = BPF(text=PROG, cflags=CFLAGS)
# Print output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"{ts} {msg}")
    except KeyboardInterrupt:
        break
