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

struct list *list_init() {
	struct list *list = (struct list *)malloc(sizeof(struct list));

	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
	list->hits = 0;
	list->misses = 0;

	return list;
}
void list_add_entry(struct list *list, unsigned long folio) {
	struct list_entry *list_entry = (struct list_entry *)malloc(sizeof(struct list_entry));

	list_entry->folio = folio;
	if (list->size == 0) {
		list_entry->prev = list_entry;
		list_entry->next = list_entry;
		list->head = list_entry;
		list->tail = list_entry;
	} else {
		list_entry->prev = list->tail;
		list_entry->next = list->head;
		list->head = list_entry;
	}

	list->size++;
}
void list_track_access(struct list *list, unsigned long folio) {
	struct list_entry *current = list->head;
	for (int i = 0; i < list->size; i++) {
		if (current->folio == folio)
			goto proc_hit;
		current = current->next;
	}
// proc_miss
	list->misses++;
	list_add_entry(list, folio);
	return;

proc_hit:
	list->hits++;
	// move entry to head
	struct list_entry *prev = current->prev;
	struct list_entry *next = current->next;
	struct list_entry *old_head = list->head;
	assert(list->size > 0);

	if (prev)
		prev->next = next;
	if (next)
		next->prev = prev;

	assert(old_head);
	old_head->prev = current;

	assert(current);
	current->prev = list->tail;
	current->next = old_head;
	return;
}

void list_evict(struct list *list, int n) {
	return;
}

void mru_update_list(struct list *list, unsigned long folio) {
	return;
}

void list_print(struct list *list) {
	struct list_entry *current = list->head;
	for (int i = 0; i < list->size; i++) {
		printf("Position: %d, Folio: %lu\n", i, current->folio);
		current = current->next;
	}
	printf("Size: %d, Hits: %d, Misses: %d\n", list->size, list->hits, list->misses);
}

struct list *list;
int handle_event(void *ctx, void *data, size_t data_size) {
	const struct event *e = data;

	list_track_access(list, e->folio);
	//printf("folio: %lu, type: %d\n", e->folio, e->type);

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

cleanup:
	page_bpf__destroy(skel);
	return -err;
}
