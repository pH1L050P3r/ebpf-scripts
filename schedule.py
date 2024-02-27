from bcc import BPF


# kprobe:finish_task_switch
# kretprobe:schedule
# tracepoint:sched:sched_switch

PROG = """
#include <linux/sched.h>

BPF_PERF_OUTPUT(output);

int print_sched_start(void* ctx){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("START PID : %d", pid);
    return 0;
}


int print_sched_end(void* ctx){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("END PID : %d", pid);
    return 0;
}


"""

# bpf_trace_printk("%d -> %ul\n", prev_tgid, prev->last_switch_time);


b = BPF(text=PROG)
b.attach_kprobe(event="schedule",fn_name="print_sched_start")
b.attach_kretprobe(event="schedule", fn_name="print_sched_end")

# Print output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"{ts} {msg}")
    except KeyboardInterrupt:
        break



