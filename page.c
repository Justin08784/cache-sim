// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "page.skel.h"
#include "common.h"
#include <stdlib.h>
#include <assert.h>
#include <utlist.h>
#include <uthash.h>


struct hash_struct {
	struct top_key key;
	struct value value;
	UT_hash_handle hh;
};

struct hash_struct *top = NULL;

void hash_add(struct top_key key) {
	struct hash_struct *h = (struct hash_struct *)malloc(sizeof(struct hash_struct));
	h->key = key;
	h->value.real_hits = 0;
	h->value.real_misses = 0;
	h->value.sim_hits = 0;
	h->value.sim_misses = 0;
	HASH_ADD(hh, top, key, sizeof(struct top_key), h);
}


struct list_entry {
	struct list_entry *prev;
	struct list_entry *next;
	unsigned long folio;
};

struct list {
	struct list_entry *head;
	struct list_entry *tail;
	int size;
	int hits;
	int misses;
};

/*
 * Page list, sorted by decreasing order of priorioty (i.e. head is max) 
 * LRU: most recent at head
 * MRU: least recent at head
 * */
struct list *list;

struct list *list_init() {
	struct list *list = (struct list *)malloc(sizeof(struct list));

	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
	list->hits = 0;
	list->misses = 0;

	return list;
}

/*
 * Inserts new el to list in LRU order. */
void list_add_entry(struct list *list, unsigned long folio) {
	struct list_entry *list_entry = (struct list_entry *)malloc(sizeof(struct list_entry));

	list_entry->folio = folio;
	DL_PREPEND(list->head, list_entry);
	// if (list->size == 0) {
	// 	list_entry->prev = list_entry;
	// 	list_entry->next = list_entry;
	// 	list->head = list_entry;
	// 	list->tail = list_entry;
	// } else {
	// 	list_entry->prev = list->tail;
	// 	list_entry->next = list->head;
	// 	list->head = list_entry;
	// }

	list->size++;
}

int count_entries(struct list *lst)
{
	struct list_entry *elt;
	int cnt;
	DL_COUNT(lst->head, elt, cnt);
	return cnt;
}

void list_track_access(struct list *list, unsigned long folio, struct top_key key, enum access_type type) {
	struct hash_struct *p;
	HASH_FIND(hh, top, &key, sizeof(struct top_key), p);
	switch (type) {
		case FMA:
			p->value.real_hits++;
		case FAF:
			p->value.real_misses++;
		case TEMP:
			p->value.real_misses++;
		case MBD:
			p->value.real_hits++;
	}

	struct list_entry *current;
	DL_SEARCH_SCALAR(list->head, current, folio, folio);
	if (current)
		goto proc_hit;
// proc_miss
	list->misses++;
	p->value.sim_misses++;
	list_add_entry(list, folio);
	return;

proc_hit:
	list->hits++;
	p->value.sim_hits++;

	int true_cnt = count_entries(list);
	assert(count_entries(list) == list->size);
	if (true_cnt != list->size)
		printf("cnt: %d, list->size: %u\n", true_cnt, list->size);

	// move entry to head
	// printf("<<<\n");
	// printf("PRE!!!\n");
	// print_lst(list);
	DL_DELETE(list->head, current);
	DL_PREPEND(list->head, current);
	// printf("POS!!!\n");
	// print_lst(list);
	// printf(">>>\n");
	return;
	// // hit, so at least 1 entry
	// assert(list->size > 0);
	// // move entry to head
	// struct list_entry *prev = current->prev;
	// struct list_entry *next = current->next;
	// struct list_entry *old_head = list->head;

	// prev->next = next;
	// next->prev = prev;

	// list->head = current;
	// old_head->prev = current;
	// current->next = old_head;

	// if (current == list->tail)
	// 	list->tail = prev;
	// current->prev = list->tail;

	// int true_cnt = count_entries(list);
	// assert(count_entries(list) == list->size);
	// if (true_cnt != list->size)
	// 	printf("cnt: %d, list->size: %u\n", true_cnt, list->size);
	// return;
}

void list_evict(struct list *list, int n) {
	struct list_entry *tail;
	assert(list->size >= n);
	list->size -= n;
	while (n--) {
		// WARNING: If this assertion fails,
		// then we have fewer elements than n to delete.
		assert(list->head);
		tail = list->head->prev;
		DL_DELETE(list->head, tail);
	}
}

/*
 * This is the counterpart of list_add_entry for MRU. */
void mru_update_list(struct list *list, unsigned long folio)
{
	struct list_entry *list_entry = (struct list_entry *)malloc(sizeof(struct list_entry));

	list_entry->folio = folio;
	DL_APPEND(list->head, list_entry);
	list->size++;
	return;
}

void list_print(struct list *list) {
	// struct list_entry *current = list->head;
	// for (int i = 0; i < list->size; i++) {
	// 	printf("Position: %d, Folio: %lu\n", i, current->folio);
	// 	current = current->next;
	// }
	// printf("Size: %d, Hits: %d, Misses: %d\n", list->size, list->hits, list->misses);

	/*
	struct list_entry *current;
	int true_cnt = 0;
	DL_FOREACH(list->head, current) {
		printf("Position: %d, Folio: %lx\n", true_cnt, current->folio);
		true_cnt++;
	}
	assert(true_cnt == list->size);
	*/
	printf("Size: %d, Hits: %d, Misses: %d\n", list->size, list->hits, list->misses);
}

int handle_event(void *ctx, void *data, size_t data_size) {
	const struct event *e = data;

	struct hash_struct *p = NULL;
	HASH_FIND(hh, top, &e->key, sizeof(struct top_key), p);
	if (!p) {
		hash_add(e->key);
	}

	list_track_access(list, e->folio, e->key, e->type);
	//printf("folio: %lu, type: %d\n", e->folio, e->type);
	//printf("key - pid: %d, uid: %d, command: %s\n", e->key.pid, e->key.uid, e->key.command);

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct page_bpf *skel;
	int err;
	struct ring_buffer *rb;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = page_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = page_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	list = list_init();
	while (!stop) {
		const int timeout_ms = 100;
		err = ring_buffer__poll(rb, timeout_ms);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}

		list_print(list);
	}

	struct hash_struct *p = NULL;
	struct hash_struct *tmp = NULL;
	printf("\n");
	printf("command\t\ttreal hit percentage\t\tsim hit percentage\n");
	HASH_ITER(hh, top, p, tmp) {
		float real_hit_percent = 100.0 * ((float)p->value.real_hits / (float)(p->value.real_hits + p->value.real_misses));
		float sim_hit_percent = 100.0 * ((float)p->value.sim_hits / (float)(p->value.sim_hits + p->value.sim_misses));
		printf("%s\t\t%f\t\t%f\n", p->key.command, real_hit_percent, sim_hit_percent);
	}

cleanup:
	page_bpf__destroy(skel);
	return -err;
}
