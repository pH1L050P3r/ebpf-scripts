from bcc import BPF

CFLAGS = ["-Wno-macro-redefined"]

program = """
int hello_world(void* ctx){
    bpf_trace_printk("Hello World!");
    return 0;
}
"""


b = BPF(text=program, cflags=CFLAGS)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_world")


b.trace_print()