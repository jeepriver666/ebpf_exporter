#include <vmlinux.h> /* 包含了所有的内部内核类型，从而避免了依赖内核层面的内核头文件 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

// Max number of disks we expect to see on the host
#define MAX_DISKS 255

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 27 //待查

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

/* 定义latency_key结构体，作为maps的key值使用 */
struct disk_latency_key_t {
    u32 dev;
    u8 op;
    u64 slot;
};

/* Kconfig extern 变量允许 BPF 程序适应不同的内核版本 —— 以及配置相关的差异 */
extern int LINUX_KERNEL_VERSION __kconfig;

/* eBPF maps
   Maps are a generic data structure for storage of different types
   of data.  They allow sharing of data between eBPF kernel
   programs, and also between kernel and user-space applications.

   Each map type has the following attributes:
    *  type
    *  maximum number of elements
    *  key size in bytes
    *  value size in bytes
 */
/* 
 * 定义maps结构体，用于内核和用户空间的数据共享
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * MAX_DISKS);
    __type(key, struct disk_latency_key_t);
    __type(value, u64);
} bio_latency_seconds SEC(".maps");

/**
 * commit d152c682f03c ("block: add an explicit ->disk backpointer to the
 * request_queue") and commit f3fa33acca9f ("block: remove the ->rq_disk
 * field in struct request") make some changes to `struct request` and
 * `struct request_queue`. Now, to get the `struct gendisk *` field in a CO-RE
 * way, we need both `struct request` and `struct request_queue`.
 * see:
 *     https://github.com/torvalds/linux/commit/d152c682f03c
 *     https://github.com/torvalds/linux/commit/f3fa33acca9f
 */
struct request_queue___x {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

/* 处理不兼容的字段和类型更改，因为不同版本的内核中有不兼容的类型。
 * 双下划线及其之后的部分，即 ___x，称为这个 struct 的 “flavor”。
 * flavor 部分会被 libbpf 忽略，这意味着在目标机器上执行字段重定位时，
 * struct request___x 匹配的仍然是真正的 struct request
 * 
 * 将此类类型用于任何 CO-RE 读取或检查。 
 * 它不必与真正的 struct request 定义完全匹配。 只有必要的字段子集必须存在且兼容。 
 * 您的 BPF 程序不需要的 struct request 之外的所有其他内容与 BPF CO-RE 无关。
 *  */
struct request___x {
    struct request_queue___x *q;
    struct gendisk *rq_disk;
/* __attribute__((preserve_access_index))有了这个属性，
 * 任何使用这个结构定义的直接内存读取都会自动地 CO-RE-relocatable。
 * 
 * 直接使用普通的 bpf_probe_read_kernel() 辅助函数，
 * 如果结构具有 preserve_access_index 属性，则此类探针读取也将变为 CO-RE-relocated
 *  */
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
    struct request___x *r = request;

    if (bpf_core_field_exists(r->rq_disk)) /* 检查给定内核类型request是否包含指定字段rq_disk */
        return BPF_CORE_READ(r, rq_disk); /* 读取request结构体中的成员：struct gendisk *rq_disk; */
    return BPF_CORE_READ(r, q, disk); /* 读取request结构体中struct request_queue结构体下的成员：struct gendisk *disk; */
}

static __always_inline int trace_rq_start(struct request *rq)
{
    /* 内核定义的函数，Return the time elapsed since system boot, in nanoseconds. */
    u64 ts = bpf_ktime_get_ns(); 

    /* bpf_map_update_elem是一个用于eBPF程序的辅助函数，
     * 它可以在给定的map中添加或更新一个键值对。它的参数有map的文件描述符，键，值和标志。
     * flags for BPF_MAP_UPDATE_ELEM command 
        #define BPF_ANY		0 /* create new element or update existing 
        #define BPF_NOEXIST	1 /* create new element if it didn't exist 
        #define BPF_EXIST	2 /* update existing element 
        #define BPF_F_LOCK	4 /* spin_lock-ed map_lookup/map_update 
     */
    bpf_map_update_elem(&start, &rq, &ts, 0);
    return 0;
}

SEC("raw_tp/block_rq_insert")
int block_rq_insert(struct bpf_raw_tracepoint_args *ctx)
{
    /**
     * commit a54895fa (v5.11-rc1) changed tracepoint argument list
     * from TP_PROTO(struct request_queue *q, struct request *rq)
     * to TP_PROTO(struct request *rq)
     */
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        return trace_rq_start((void *) ctx->args[1]);
    } else {
        return trace_rq_start((void *) ctx->args[0]);
    }
}

SEC("raw_tp/block_rq_issue")
int block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
    /**
     * commit a54895fa (v5.11-rc1) changed tracepoint argument list
     * from TP_PROTO(struct request_queue *q, struct request *rq)
     * to TP_PROTO(struct request *rq)
     */
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        return trace_rq_start((void *) ctx->args[1]);
    } else {
        return trace_rq_start((void *) ctx->args[0]);
    }
}

SEC("raw_tp/block_rq_complete")
int block_rq_complete(struct bpf_raw_tracepoint_args *ctx)
{
    u64 *tsp, flags, delta_us, latency_slot;
    struct gendisk *disk;
    struct request *rq = (struct request *) ctx->args[0];
    struct disk_latency_key_t latency_key = {};

    /* bpf_map_lookup_elem是一个用于eBPF程序的辅助函数，它可以在给定的map中查找一个键对应的值。 */
    tsp = bpf_map_lookup_elem(&start, &rq);
    if (!tsp) {
        return 0;
    }

    // Delta in microseconds
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // Latency histogram key
    latency_slot = log2l(delta_us);

    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    disk = get_disk(rq);
    flags = BPF_CORE_READ(rq, cmd_flags); /* 读取内核数据rq->cmd_flags, op and common flags  */

    latency_key.slot = latency_slot;
    latency_key.dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
    latency_key.op = flags & REQ_OP_MASK;

    increment_map(&bio_latency_seconds, &latency_key, 1);

    latency_key.slot = MAX_LATENCY_SLOT + 1;
    increment_map(&bio_latency_seconds, &latency_key, delta_us);

    /* bpf_map_delete_elem是一个用于eBPF程序的辅助函数，它可以在给定的map中删除一个键对应的元素。 */
    bpf_map_delete_elem(&start, &rq);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
