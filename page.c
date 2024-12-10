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


struct list_entry {
	struct list_entry *prev;
	struct list_entry *next;
	unsigned long folio;
};

struct task_stats_entry {
	struct task_key key;
	int hits;
	int misses;
	UT_hash_handle hh;
};

struct policy_simulation {
	struct list_entry *list_head;
	struct task_stats_entry *task_stats;
	void (*hit_update)(struct policy_simulation *, struct list_entry *);
	void (*miss_update)(struct policy_simulation *, unsigned long);
	int hits;
	int misses;
};

struct task_stats_entry *linux_task_stats = NULL;
struct policy_simulation *ps;
FILE *log_file;

struct policy_simulation *policy_simulation_init(void (*hit_update)(struct policy_simulation *, struct list_entry *), void (*miss_update)(struct policy_simulation *, unsigned long)) {
	struct policy_simulation *ps = (struct policy_simulation *)malloc(sizeof(struct policy_simulation));

	// uthash requires its lists and hash tables to be initialized with NULL
	ps->list_head = NULL;
	ps->task_stats = NULL;
	ps->hit_update = hit_update;
	ps->miss_update = miss_update;
	ps->hits = 0;
	ps->misses = 0;

	return ps;
}

void policy_simulation_track_access(struct policy_simulation *ps, const struct event *e) {
	struct task_stats_entry *tse = NULL;
	HASH_FIND(hh, linux_task_stats, &e->key, sizeof(struct task_key), tse);
	if (!tse) {
		tse = (struct task_stats_entry *)malloc(sizeof(struct task_stats_entry));
		tse->key = e->key;
		tse->hits = 0;
		tse->misses = 0;
		HASH_ADD(hh, linux_task_stats, key, sizeof(struct task_key), tse);
	}
	switch (e->type) {
		case FMA:
			tse->hits++;
			break;
		case FAF:
			tse->misses++;
			break;
		case TEMP:
			tse->misses++;
			break;
		case MBD:
			tse->hits++;
			break;
		default:
			return;
			break;
	}

	HASH_FIND(hh, ps->task_stats, &e->key, sizeof(struct task_key), tse);
	if (!tse) {
		tse = (struct task_stats_entry *)malloc(sizeof(struct task_stats_entry));
		tse->key = e->key;
		tse->hits = 0;
		tse->misses = 0;
		HASH_ADD(hh, ps->task_stats, key, sizeof(struct task_key), tse);
	}

	struct list_entry *entry = NULL;
	DL_SEARCH_SCALAR(ps->list_head, entry, folio, e->folio);
	if (entry) {
		ps->hits++;
		tse->hits++;
		(*ps->hit_update)(ps, entry);
	} else {
		ps->misses++;
		tse->misses++;
		(*ps->miss_update)(ps, e->folio);
	}
}


int policy_simulation_size(struct policy_simulation *ps) {
	struct list_entry *entry;
	int size;
	DL_COUNT(ps->list_head, entry, size);
	return size;
}

void policy_simulation_evict(struct policy_simulation *ps, int num_to_evict) {
	printf("TODO: fix policy_simulation_evict\n");
	int size = policy_simulation_size(ps);
	printf("Size: %d, num_to_evict: %d\n", size, num_to_evict);
	if (num_to_evict >= size) return;
	while(num_to_evict--) {
		struct list_entry *del_entry = ps->list_head;
		DL_DELETE(ps->list_head, del_entry);
		/*
		if (del_entry->payload) {
			free(del_entry->payload);
		}
		*/
		free(del_entry);
	}
}

void policy_simulation_print(struct policy_simulation *ps) {
	/*
	struct list_entry *entry;
	int position = 0;
	DL_FOREACH(ps->list_head, entry) {
		printf("Position: %d, Folio: %lu\n", position++, entry->folio);
	}
	*/

	printf("Size: %d, Hits: %d, Misses: %d\n", policy_simulation_size(ps), ps->hits, ps->misses);
}

void mru_hit_update(struct policy_simulation *ps, struct list_entry *hit_entry) {
	// Remove hit_entry from the list
	DL_DELETE(ps->list_head, hit_entry);
	// Make hit_entry the new head of the list
	DL_PREPEND(ps->list_head, hit_entry);
}

void mru_miss_update(struct policy_simulation *ps, unsigned long folio) {
	struct list_entry *entry = (struct list_entry *)malloc(sizeof(struct list_entry));
	entry->folio = folio;

	// Make entry the new head of the list
	DL_PREPEND(ps->list_head, entry);
}


int handle_event(void *ctx, void *data, size_t data_size) {
	const struct event *e = data;

	fprintf(log_file, "%lu,%d,%d,%d,%s\n", e->folio, e->type, e->key.uid, e->key.pid, e->key.command);

	if (e->type == SFL) {
		policy_simulation_evict(ps, e->num_evicted);
		return 0;
	}

	policy_simulation_track_access(ps, e);

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

	ps = policy_simulation_init(&mru_hit_update, &mru_miss_update);
	log_file = fopen("page.log", "w");
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

		policy_simulation_print(ps);
	}
	fclose(log_file);

	struct task_stats_entry *tse = NULL;
	struct task_stats_entry *tmp = NULL;
	printf("\n");
	printf("%-16s    %-16s    %-16s\n", "Command", "Real Hit %", "Sim Hit %");
	HASH_ITER(hh, linux_task_stats, tse, tmp) {
		float real_hit_percent = 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));

		struct task_key key = tse->key;
		HASH_FIND(hh, ps->task_stats, &key, sizeof(struct task_key), tse);
		float sim_hit_percent = 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));

		//if (p->value.real_hits + p->value.sim_hits > 100) {
		printf("%-16s    %-16.2f    %-16.2f\n", tse->key.command, real_hit_percent, sim_hit_percent);
	}

cleanup:
	page_bpf__destroy(skel);
	return -err;
}
