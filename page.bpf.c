// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "page.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct list;
struct list_entry;
struct event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * sizeof(struct event));
} events SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);     // Define the map type
//     __uint(max_entries, 4096);           // Maximum number of entries
//     __type(key, int);                   // Key type
//     __type(value, int);                 // Value type
// } shared_map SEC(".maps");



unsigned long get_pfn_folio(struct folio *folio) {
	unsigned long page_addr = (unsigned long)(folio + offsetof(struct folio, page));
	unsigned long pfn = page_addr / 4096; // TODO
	return pfn;
}
unsigned long get_pfn_buffer_head(struct buffer_head *bh) {
	unsigned long page_addr = (unsigned long)(BPF_CORE_READ(bh, b_page));
	unsigned long pfn = page_addr / 4096; // TODO
	return pfn;
}

long order_id = 0;
static long send_event(struct folio *fol, enum event_type etyp)
{
    static unsigned long order_id = 0;
    struct event *e;
    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    // NOTE: I believe reservation makes updates atomic
    // e->order_id = __sync_fetch_and_add(&order_id, 1);
    if (!e)
        return -1;

    /* send data to user-space for post-processing */
    e->folio_ptr = (unsigned long)fol;
    e->etyp = etyp;
    e->order_id = __sync_fetch_and_add(&order_id, 1);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(folio_mark_accessed, struct folio *folio)
{
	pid_t pid;
	unsigned long pfn;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_folio(folio);
	bpf_printk("folio_mark_accessed: pid = %d, pfn=%ul\n", pid, pfn);

        send_event(folio, MPA);

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
	bpf_printk("filemap_add_folio: pid = %d, pfn=%ul\n", pid, pfn);

        send_event(folio, APCL);
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
	bpf_printk("KPROBE ENTRY pid = %d, pfn=%ul\n", pid, pfn);


        /*WARNING: Is this the right event type?*/
        send_event(folio, APD);
	return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(mark_buffer_dirty, struct buffer_head *bh)
{
	pid_t pid;
	unsigned long pfn;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_buffer_head(bh);
	bpf_printk("mark_buffer_dirty: pid = %d, pfn=%ul\n", pid, pfn);
        // BUG: b_folio doesn't work. So I'm cheating and using b_page instead.
	// struct folio *folio = (unsigned long)(BPF_CORE_READ(bh, b_folio));
	struct folio *folio = (unsigned long)(BPF_CORE_READ(bh, b_page));

        send_event(folio, MBD);
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
