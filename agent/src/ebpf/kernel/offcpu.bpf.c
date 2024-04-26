/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

/*
 * It works by tracking when threads are blocked and when they return
 * to the CPU, measuring their time spent in the "off-CPU" state along with
 * the blocked stack trace and task name. The output summary assists in
 * identifying the reasons for thread blocking and quantifying their time
 * spent in the "off-CPU" state. This encompasses typical blocking activities
 * in user programs such as disk I/O, network I/O, locks, etc.
 */

#include "offcpu.h"

/* *INDENT-OFF* */

MAP_ARRAY(start_pid_map, int, int, 1)
struct data_args_t {
	unsigned long addr;
        unsigned long len;
	unsigned long fd;
	__u64 ts;
};
BPF_HASH(active_read_args_map, __u64, struct data_args_t)
struct mmap_data_t {
	unsigned long real_addr;
        unsigned long addr;
        unsigned long len;
        unsigned long fd;
        __u64 ts;
	int pid;
	int tgid;
	char comm[16];
};
BPF_HASH(active_mmap_map, __u64, struct mmap_data_t, 10000)
/* *INDENT-ON* */

// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
TP_SCHED_PROG(sched_process_exec) (struct sched_switch_ctx * ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = (__u32) id;
	if (pid == tid) {
		char comm[TASK_COMM_LEN];
		bpf_get_current_comm(comm, sizeof(comm));
		// deepflow-agent
		if ((comm[9] == 'a' && comm[10] == 'g'
		     && comm[11] == 'e' && comm[12] == 'n')) {
			int key = 0;
			start_pid_map__update(&key, &pid);
		}
	}

	return 0;
}

struct syscall_mmap_enter_ctx {
	unsigned short common_type;	//offset:0;	size:2;	signed:0;
	unsigned char common_flags;	//offset:2;	size:1;	signed:0;
	unsigned char common_preempt_count;	//offset:3;	size:1;	signed:0;
	int common_pid;	//offset:4;	size:4;	signed:1;

	int __syscall_nr;	//offset:8;	size:4;	signed:1;
	unsigned long addr;	//offset:16;	size:8;	signed:0;
	unsigned long len;	//offset:24;	size:8;	signed:0;
	unsigned long prot;	//offset:32;	size:8;	signed:0;
	unsigned long flags;	//offset:40;	size:8;	signed:0;
	unsigned long fd;	//offset:48;	size:8;	signed:0;
	unsigned long off;	//offset:56;	size:8;	signed:0;
};

TPPROG(sys_enter_mmap) (struct syscall_mmap_enter_ctx * ctx) {
        int key = 0;
        int *filter_pid = start_pid_map__lookup(&key);
        if (filter_pid == NULL)
                return 0;

        __u64 id = bpf_get_current_pid_tgid();
        if ((id >> 32) != *filter_pid)
                return 0;

	struct data_args_t read_args = {};
        read_args.fd = ctx->fd;
        read_args.addr = ctx->addr;
        read_args.ts = bpf_ktime_get_ns();
	read_args.len = ctx->len;
        active_read_args_map__update(&id, &read_args);
	return 0;	
}

struct syscall_mmap_exit_ctx {
	unsigned short common_type;	//offset:0;     size:2; signed:0;
	unsigned char common_flags;	//offset:2;     size:1; signed:0;
	unsigned char common_preempt_count;	//offset:3;     size:1; signed:0;
	int common_pid;		//offset:4;     size:4; signed:1;

	int __syscall_nr;	//offset:8;     size:4; signed:1;
	long ret;		//offset:16;    size:8; signed:1;
};

TPPROG(sys_exit_mmap) (struct syscall_mmap_exit_ctx * ctx) {
        __u64 id = bpf_get_current_pid_tgid();
        struct data_args_t *read_args = active_read_args_map__lookup(&id);
        // Don't process FD 0-2 to avoid STDIN, STDOUT, STDERR.
        if (read_args == NULL) {
		return 0;
        }

	if (ctx->ret <= 0) {
		active_read_args_map__delete(&id);
		return 0;
	}

	__u64 key = ctx->ret;
	struct mmap_data_t data;
        data.addr = read_args->addr;
        data.len = read_args->len;
        data.fd = read_args->fd;
        data.ts = read_args->ts;
	data.real_addr = key;
	data.pid = (int)id;
	data.tgid = id >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

	active_mmap_map__update(&key, &data);

	active_read_args_map__delete(&id);
	return 0;
}

struct syscall_munmap_enter_ctx {
	unsigned short common_type;	//offset:0;     size:2; signed:0;
	unsigned char common_flags;	//offset:2;     size:1; signed:0;
	unsigned char common_preempt_count;	//offset:3;     size:1; signed:0;
	int common_pid;

	int __syscall_nr;	// offset:8;          //size:4;       signed:1;
	unsigned long addr;	//offset:16;    size:8; signed:0;
	size_t len;		//offset:24;    size:8; signed:0;
};

TPPROG(sys_enter_munmap) (struct syscall_munmap_enter_ctx * ctx) {
	int key = 0;
	int *filter_pid = start_pid_map__lookup(&key);
	if (filter_pid == NULL)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	if ((id >> 32) != *filter_pid)
		return 0;

	__u64 addr = ctx->addr;

	active_mmap_map__delete(&addr);

	return 0;
}

#if 0
static inline int record_sched_info(struct sched_switch_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();

	// CPU idle process does not perform any processing.
	if (id >> 32 == 0 && (__u32) id == 0)
		return -1;

	/* TODO: Threads filter */

	/* 
	 * On Linux, involuntary context switches occur for state TASK_RUNNING,
	 * whereas the blocking events we're usually interested in are in
	 * TASK_INTERRUPTIBLE (0x01) or TASK_UNINTERRUPTIBLE (0x02).
	 *
	 * TASK_INTERRUPTIBLE ('S'): interruptible sleep (waiting for an event to complete)
	 * TASK_UNINTERRUPTIBLE ('D'): uninterruptible sleep (usually IO)
	 */
	if (!(((ctx->prev_state & (TASK_REPORT_MAX - 1)) & 0x01)
	      || ((ctx->prev_state & (TASK_REPORT_MAX - 1)) & 0x02)))
		return -1;

	// Filter out the high volume of scheduling events caused by self-monitoring.
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	if ((comm[0] == 't' && comm[1] == 'c' && comm[2] == '\0')
	    || (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h')
	    || (comm[0] == 'p' && comm[1] == 'e' && comm[2] == 'r'))
		return -1;

	struct sched_info_s val = {};
	val.prev_pid = ctx->prev_pid;
	int pid = ctx->next_pid;
	offcpu_sched_map__update(&pid, &val);

	return 0;
}

static inline __u64 fetch_delta_time(int curr_pid, int offcpu_pid)
{
	int pid = curr_pid;
	int prev_pid = offcpu_pid;
	__u64 ts, *tsp;
	ts = bpf_ktime_get_ns();
	offcpu_start_map__update(&prev_pid, &ts);
	tsp = offcpu_start_map__lookup(&pid);
	if (tsp == NULL)
		return 0;

	// calculate schedule thread's delta time
	__u64 delta_ns = ts - *tsp;
	offcpu_start_map__delete(&pid);

	/*
	 * Note:
	 * Scheduler events are still high-frequency events, as their rate may exceed
	 * 1 million events per second, so caution should still be exercised.
	 *
	 * If overhead remains an issue, you can check the 'MINBLOCK_US' tunable parameter
	 * in the code. If your goal is to trace longer blocking events, then increasing
	 * this parameter can filter out shorter blocking events, further reducing overhead.
	 */
	__u64 delta_us = delta_ns / 1000;
	if ((delta_us < MINBLOCK_US) || (delta_us > MAXBLOCK_US))
		return 0;

	return delta_ns;
}

// The current task is a new task that has been scheduled.
static inline int oncpu(struct pt_regs *ctx, int pid, int tgid, __u64 delta_ns)
{
	// create map key
	struct offcpu_data_s data = {};
	data.userstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
					 USER_STACKID_FLAGS);

	/* 
	 * It only handles user-space programs. If there's no
	 * user-space stack, it won't process.
	 */
	if (data.userstack < 0)
		return 0;

	data.kernstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
					 KERN_STACKID_FLAGS);
	data.pid = pid;
	data.tgid = tgid;
	data.duration_ns = delta_ns;
	bpf_get_current_comm(&data.name, sizeof(data.name));

	bpf_perf_event_output(ctx, &NAME(offcpu_output_a),
			      BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

/*
 * Here is an indication of where the probes are located:
 *
 * schedule() -> trace_sched_switch -> switch_to() -> finish_task_switch()                  
 *                (oncpu old task)    stack switch      (oncpu new task) 
 */

// /sys/kernel/debug/tracing/events/sched/sched_switch/format 
TP_SCHED_PROG(sched_switch) (struct sched_switch_ctx * ctx) {
	return record_sched_info(ctx);
}

// static struct rq *finish_task_switch(struct task_struct *prev)
KPROG(finish_task_switch) (struct pt_regs * ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int pid = (int)id, tgid = (int)(id >> 32);
	struct sched_info_s *v;
	v = offcpu_sched_map__lookup(&pid);
	if (v == NULL)
		return 0;

	int prev_pid = v->prev_pid;
	offcpu_sched_map__delete(&pid);

	__u64 delta_ns = fetch_delta_time(pid, prev_pid);
	if (delta_ns == 0)
		return 0;

	return oncpu(ctx, pid, tgid, delta_ns);
}
#endif
