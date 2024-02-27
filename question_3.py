from bcc import BPF


PROG = """
BPF_HASH(counter_table);

int increment_sys_call_entry(void* ctx){
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *p = counter_table.lookup(&d);

    if(p != NULL){
    
    }
}

"""