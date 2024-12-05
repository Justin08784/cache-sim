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
#include "page.h"
#include <stdlib.h>
#include <assert.h>

struct list;
struct list_entry;
struct event;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}



static int handle_event(void *ctx, void *data, size_t data_sz)
{
// void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct event *e = data;
    printf("(%lu) Folio Addr: %lx, Type: %d\n", e->order_id, e->folio_ptr, e->etyp);
    return -1;
}

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
        free(tmp);
        cnt++;
    }

    if (cnt < n) {
        // there are fewer than n list entries
        assert(cur == NULL);
    }

    cur->next = NULL;
}

void mru_update_list(struct list *list, unsigned long pfn) {
    struct list_entry *prev_head = list->head;

    // WARNING: need to create shared map for list heads?
    // no alloc allowed in ebpf
    struct list_entry *new_head = malloc(sizeof(struct list_entry));
    assert(new_head);

    new_head->next = prev_head;
    if (prev_head)
        prev_head->prev = new_head;
    list->head = new_head;
}


int main(int argc, char **argv)
{
	struct page_bpf *skel;
	int err;

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

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
        // int map_fd = bpf_map__fd(skel->maps.shared_map);
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);

        while (!stop) {
            ring_buffer__poll(rb, 100); // Poll for events
        }


	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	page_bpf__destroy(skel);
	return -err;
}
