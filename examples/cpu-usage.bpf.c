#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "maps.bpf.h"



//#include <linux/string.h>  


#define MAX_PID_NUM  (4 * 1024 * 1024)

#define MAX_COMM_NAME 16


struct thread_info_t {
    u64 cpu_num;
    u64 pid;
    // u64 once_time;
};

struct thread_count_t {
    u64 cpu_num;
    u64 pid;
    // u64 once_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u64);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_NUM);
    __type(key, struct thread_count_t);
    __type(value, u64);
} raw_sched_switch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_NUM);
    __type(key, struct thread_count_t);
    __type(value, u64);
} raw_sched_switch_pid_count SEC(".maps");


// SEC("raw_tp/sched_switch")
// int BPF_PROG(sched_switch_tp, bool preempt, struct task_struct *prev,
// 	     struct task_struct *next)

SEC("raw_tp/sched_switch")
// SEC("tracepoint/sched/sched_switch")
int raw_sched_switch_test(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev, *next;
    struct thread_info_t thread_info;
    struct thread_count_t thread_count;

    u64 ts, *tsp, delta, cpu_id;
    u32 prev_pid, next_pid;

    prev = (struct task_struct *) ctx->args[1];
    next = (struct task_struct *) ctx->args[2];

    prev_pid = (u32)BPF_CORE_READ(prev, pid);
    next_pid = (u32)BPF_CORE_READ(next, pid);
    cpu_id = bpf_get_smp_processor_id();

    thread_count.cpu_num = cpu_id;
    thread_count.pid = prev_pid;
    increment_map(&raw_sched_switch_pid_count, &thread_count, 1);

    // bpf_printk("prev_pid: %d, next_pid: %d, cpu_id: %d \n", prev_pid, next_pid, cpu_id);

	ts = bpf_ktime_get_ns();
    // bpf_printk("ts: %ld \n", ts);

    tsp = bpf_map_lookup_elem(&start, &cpu_id);
    // bpf_printk("prev_pid: %d, cpu: %d, tsp: %ld \n", prev_pid, cpu_id, *tsp);

    // tsp = bpf_map_lookup_elem(&start, &next_pid);
    // bpf_printk("next_pid: %d, cpu: %d, tsp: %ld \n", next_pid, cpu_id, tsp);
    if (prev_pid && tsp) 
    {   // when tsp is NULL, it means we are first running. 

        thread_info.cpu_num = cpu_id;
        thread_info.pid = prev_pid;
        delta = (ts - *tsp) / 1000;  // us

//        bpf_map_update_elem(&raw_sched_switch, &thread_info, &tmp, BPF_ANY);

        increment_map(&raw_sched_switch, &thread_info, delta);

        bpf_printk("pid: %d, cpu_num: %d, delta time: %ld \n", 
                    thread_info.pid, thread_info.cpu_num, delta);
    }
    
    /////////////////////////////

    // bpf_map_update_elem(&start, &next_pid, &ts, 0);
    bpf_map_update_elem(&start, &cpu_id, &ts, 0);

    return 0;
}   

char LICENSE[] SEC("license") = "GPL";