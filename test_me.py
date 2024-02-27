from bcc import BPF
from time import sleep


# kprobe:finish_task_switch
# kretprobe:schedule
# tracepoint:sched:sched_switch

PROG = r"""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(output);

TRACEPOINT_PROBE(sched, sched_switch)
{
    u32 p_pid = args->prev_pid;
    u32 n_pid = args->next_pid;

    bpf_trace_printk("START PID : %d,  END : %d\n", p_pid, n_pid);
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
# b.attach_kretprobe(event="schedule", fn_name="func_sched_stop")

b.trace_print()


