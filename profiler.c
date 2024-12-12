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
#include "profiler.skel.h"
#include "common.h"
#include <stdlib.h>
#include <assert.h>
#include <utlist.h>
#include <uthash.h>


FILE *log_file;
unsigned long event_counter;


int handle_event(void *ctx, void *data, size_t data_size) {
	const struct event *e = data;

	fprintf(log_file, "%lu,%d,%d,%d,%s\n", e->data, e->type, e->key.uid, e->key.pid, e->key.command);
	printf("Events Logged: %-32lu\r", event_counter++);
	fflush(stdout);

	//policy_simulation_track_access(ps, e);

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
	struct profiler_bpf *skel;
	int err;
	struct ring_buffer *rb;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = profiler_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = profiler_bpf__attach(skel);
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

	printf("\n");
	event_counter = 0;
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
	}
	fclose(log_file);
	printf("Events Logged: %-32lu\n", event_counter);

cleanup:
	profiler_bpf__destroy(skel);
	return -err;
}
