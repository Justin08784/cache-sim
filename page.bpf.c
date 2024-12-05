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
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

void send_event(struct folio *folio, enum access_type type) {
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		// TODO
		return;
	}

	e->folio = (unsigned long)folio;
	e->type = type;

	bpf_ringbuf_submit(e, 0);
}
unsigned long get_pfn_folio(struct folio *folio) {
	unsigned long page_addr = (unsigned long)(folio + offsetof(struct folio, page));
	unsigned long pfn = page_addr;// / 4096; // TODO
	return pfn;
}
unsigned long get_pfn_buffer_head(struct buffer_head *bh) {
	unsigned long page_addr = (unsigned long)(BPF_CORE_READ(bh, b_page));
	unsigned long pfn = page_addr;// / 4096; // TODO
	return pfn;
}


SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(folio_mark_accessed, struct folio *folio)
{
	pid_t pid;
	unsigned long pfn;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_folio(folio);
	send_event(folio, FMA);
	bpf_printk("folio_mark_accessed: pid = %d, pfn=%lu\n", pid, pfn);

	return 0;
}

typedef int pgoff_t;
SEC("kprobe/filemap_add_folio")
int BPF_KPROBE(filemap_add_folio, struct address_space *mapping, struct folio *folio, pgoff_t index, gfp_t gfp)
{
	pid_t pid;
	unsigned long pfn;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_folio(folio);
	send_event(folio, FAF);
	bpf_printk("filemap_add_folio: pid = %d, pfn=%lu\n", pid, pfn);

	return 0;
}

// SEC("kprobe/folio_account_dirtied")
SEC("kprobe/__folio_mark_dirty")
int BPF_KPROBE(__folio_mark_dirty, struct folio *folio, struct address_space *mapping)
{
	pid_t pid;
	unsigned long pfn;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_folio(folio);
	send_event(folio, TEMP);
	bpf_printk("__folio_mark_dirty pid = %d, pfn=%lu\n", pid, pfn);

	return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(mark_buffer_dirty, struct buffer_head *bh)
{
	pid_t pid;
	unsigned long pfn;
	struct folio *folio;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_buffer_head(bh);
	folio = (struct folio *)BPF_CORE_READ(bh, b_page);
	send_event(folio, MBD);
	bpf_printk("mark_buffer_dirty: pid = %d, pfn=%lu\n", pid, pfn);

	return 0;
}

/*
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}
*/
