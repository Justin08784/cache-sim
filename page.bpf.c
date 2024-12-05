// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <assert.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct list_entry {
	struct list_entry *next;
        struct list_entry *prev;
	unsigned long pfn;
};

struct list {
	struct list_entry *head;
	struct list_entry *tail;
	int hits;
	int misses;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);     // Define the map type
    __uint(max_entries, 2);           // Maximum number of entries
    __type(key, int);                   // Key type
    __type(value, int);                 // Value type
} shared_map SEC(".maps");

void list_track_access(struct list *list, unsigned long pfn) {
    struct list_entry *cur = list->head;
    // WARNING: what to do with hits/misses?
    while(!cur) {
        if (cur->pfn != pfn) {
            cur = cur->next;
            continue;
        }

        // found
        list->hits++;
        return;
    }

    list->misses++;
}

void list_evict(struct list *list, int n) {
    // NOTE: I am assuming n == pfn
    int cnt = 0;
    struct list_entry *cur = list->tail;
    struct list_entry *tmp;

    while (!cur && cnt < n) {
        tmp = cur;
        cur = cur->prev;
        // free(tmp);
        cnt++;
    }

    // if (cnt < n) {
    //     // there are fewer than n list entries
    //     assert(cur == NULL);
    // }

    cur->next = NULL;
}

void mru_update_list(struct list *list, unsigned long pfn) {
    struct list_entry *prev_head = list->head;

    // WARNING: need to create shared map for list heads?
    // no alloc allowed in ebpf
    // struct list_entry *new_head = malloc(sizeof(struct list_entry));
    // struct list_entry *new_head = NULL;

    // new_head->next = prev_head;
    // if (prev_head)
    //     prev_head->prev = new_head;
    // list->head = new_head;
}


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

struct event {
    uint32_t key;
    uint32_t value;
};

SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(folio_mark_accessed, struct folio *folio)
{
	pid_t pid;
	unsigned long pfn;

	pid = bpf_get_current_pid_tgid() >> 32;
	pfn = get_pfn_folio(folio);
	bpf_printk("folio_mark_accessed: pid = %d, pfn=%ul\n", pid, pfn);

        struct event *e;
    	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->key = pid;
	e->value = 42;

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	// __sync_fetch_and_add(&read, 1);

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
