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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


struct event {
    uint32_t key;
    uint32_t value;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
// void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct event *e = data;
    printf("Key: %d, Value: %d\n", e->key, e->value);
    return -1;
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
        int map_fd = bpf_map__fd(skel->maps.shared_map);
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
