from bcc import BPF


# kprobe:finish_task_switch
# kretprobe:schedule
# tracepoint:sched:sched_switch

PROG = """
#include <linux/sched.h>
#include <linux/ptrace.h>

BPF_PERF_OUTPUT(output);

// TRACEPOINT_PROBE(sched, sched_switch)
int func_sched_start(struct __sk_buff *skb)
{
    struct sched_switch_args *args = (struct sched_switch_args *)skb->data;
    struct task_struct *prev = args->args[1];
    struct task_struct *next = args->args[2];
    u32 prev_tgid, next_tgid;
    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_trace_printk("START PID : %d", prev_tgid);
    return 0;
}


int func_sched_stop(void* ctx){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("END PID : %d", pid);
    return 0;
}
"""

# bpf_trace_printk("%d -> %ul\n", prev_tgid, prev->last_switch_time);


b = BPF(text=PROG)
# b.attach_tracepoint(tp="sched:sched_switch", fn_name="func_sched_start")
b.attach_kretprobe(event="schedule", fn_name="func_sched_stop")

# Print output
while True:
    try:
        out = b.trace_fields()
        print(out)
    except KeyboardInterrupt:
        break



