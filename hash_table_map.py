from time import sleep
from bcc import BPF

CFLAGS = ["-Wno-macro-redefined"]

program = """
// defined hash map with name counter_table
BPF_HASH(counter_table);

int hello_map(void *ctx){
    u64 uid;
    u64 counter = 0;
    u64 *p;

    // Help to obtain the user Id of current running process which triggers the event
    // first 32 bit = group id
    // last 32 bit = user id
    // so = id & 0xFFFFFFFF = USER_ID(last 32 bit)
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // look for entry in hash table
    // returns pointer to that entry otherwise NULL = 0
    p = counter_table.lookup(&uid);
    if(p != 0){
        counter = *p;
    }
    counter++;
    // Update the entry in hash table
    counter_table.update(&uid, &counter);
    return 0;
}
"""


b = BPF(text=program, cflags=CFLAGS)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_map")


# above code loads code into kernel
# now we need to read the map for user program


while True:
    sleep(2);
    s = ""
    print("-"*50)
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\n"
    print(s, end="")
    print("-"*50)