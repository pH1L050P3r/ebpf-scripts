from bcc import BPF
from time import sleep

CFLAGS = ["-Wno-macro-redefined"]

program = """
struct data_t {
    u64 id;
    char command[128];
};

BPF_HASH(counter_table, struct data_t, u64);

int sys_call_handler(void* ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t d = {.id = pid};
    bpf_get_current_comm(&d.command, sizeof(d.command));

    u64 *p = counter_table.lookup(&d);
    u64 count = 0;

    if(p != NULL){
        count = *p;
    }
    count += 1;
    counter_table.update(&d, &count);
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
        s += f"ID : {k.id} | Command : {k.command} | count : {v.value}\n"
    print('\033c', end="")
    print(s, end="", flush=True)