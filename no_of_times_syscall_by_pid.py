from bcc import BPF
from time import sleep

CFLAGS = ["-Wno-macro-redefined"]

program = """
BPF_HASH(counter_table);

int sys_call_handler(void* ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *p = counter_table.lookup(&pid);
    u64 count = 0;

    if(p != NULL){
        count = *p;
    }
    count++;
    counter_table.update(&pid, &count);
    return 0;
}
"""


b = BPF(text=program, cflags=CFLAGS)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="sys_call_handler")


# above code loads code into kernel
# now we need to read the map for user program


while True:
    sleep(2);
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\n"
    print('\033c', end="")
    print(s, end="", flush=True)