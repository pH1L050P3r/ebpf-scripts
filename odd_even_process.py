from bcc import BPF

CFLAGS = ["-Wno-macro-redefined"]

program = """
/*
Here we put data into ring buffer instead of trace_pipe
*/

BPF_PERF_OUTPUT(output);

struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[128];
};

int perf_ring_output(void* ctx){
    struct data_t data = {};
    char message[128] = "";
    // First 32 bit is process Id 
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if(data.pid % 2){
        strcpy(message, "I am process with odd ID");
    } else {
        strcpy(message, "I am process with event ID");
    }

    // function for getting the name of the executable that's running in the process
    bpf_get_current_comm(&data.command, sizeof(data.command));
    
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


b = BPF(text=program, cflags=CFLAGS)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="perf_ring_output")


# above code loads code into kernel
# now we need to read the perf ring for user program

def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# opens perf ring and takes callback function to be user whenever there is a data to read from the buffer
b["output"].open_perf_buffer(print_event)
while True:
    # If any data present in  perf buffer then print_event will be called
    b.perf_buffer_poll()