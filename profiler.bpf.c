// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1200 * 1024 /* 1200 KB */);
} events SEC(".maps");

void send_event(unsigned long data, enum access_type type) {
	struct event *e;
	struct task_key key;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_printk("bpf_ringbuf_reserve failed\n");
		return;
	}

	key.uid = bpf_get_current_uid_gid();
	key.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&key.command, 16);

	e->data = data;
	e->type = type;
	e->key = key;

	bpf_ringbuf_submit(e, 0);
}


SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(folio_mark_accessed, struct folio *folio)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	send_event((unsigned long)folio, FMA);
	//bpf_printk("folio_mark_accessed: pid = %d\n", pid);

	return 0;
}

typedef int pgoff_t;
SEC("kprobe/filemap_add_folio")
int BPF_KPROBE(filemap_add_folio, struct address_space *mapping, struct folio *folio, pgoff_t index, gfp_t gfp)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	send_event((unsigned long)folio, FAF);
	//bpf_printk("filemap_add_folio: pid = %d\n", pid);

	return 0;
}

/*
 * We cannot hook into folio account dirtied, so we hook into
 * __folio_mark_dirty, which calls folio_account_dirtied if
 * folio->mapping is not null.
 */
SEC("kprobe/__folio_mark_dirty")
int BPF_KPROBE(__folio_mark_dirty, struct folio *folio, struct address_space *mapping)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (BPF_CORE_READ(folio, mapping)) {
		send_event((unsigned long)folio, FMD);
		//bpf_printk("__folio_mark_dirty: pid = %d\n", pid);
	}

	return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(mark_buffer_dirty, struct buffer_head *bh)
{
	pid_t pid;
	struct folio *folio;

	pid = bpf_get_current_pid_tgid() >> 32;
	/*
	 * The buffer_head struct holds the b_page in a union with b_folio,
	 * but b_folio does not exist in the buffer_head struct defined by
	 * vm_linux.h. The b_page pointer should be the same as the
	 * b_folio pointer.
	 */
	folio = (struct folio *)BPF_CORE_READ(bh, b_page);
	send_event((unsigned long)folio, MBD);
	//bpf_printk("mark_buffer_dirty: pid = %d\n", pid);

	return 0;
}

SEC("kretprobe/shrink_folio_list")
int BPF_KRETPROBE(shrink_folio_list, unsigned int ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	send_event(ret, SFL);
	//bpf_printk("shrink_folio_list: pid = %d, ret = %ld\n", pid, ret);

	return 0;
}

/*
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exec *ctx) {
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("sched_process_exit: pid = %d\n", pid);

	return 0;
}
*/
