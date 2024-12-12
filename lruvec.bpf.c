// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";


void __always_inline print_lru_list(struct list_head list) {
	// Get pointer to the start of the list in the kernel's virtual address space
	struct list_head *start = BPF_CORE_READ(list.next, prev);
	struct list_head *current = list.next;
	bpf_printk("start=%p, current=%p diff=%d\n", start, current, start!=current);

	const int max_list_size = 1024; // TODO: Modify this value as needed
	for (int i = 0; i < max_list_size; i++) {
		if (start == current) {
			break;
		}

		struct folio *f = (struct folio *)(current - offsetof(struct folio, lru));
		bpf_printk("Position: %d, Folio: %lu\n", i, f);
		current = BPF_CORE_READ(current, next);
	}
}


SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exec *ctx) {
	pid_t pid;
	int cgroup_id;

	pid = bpf_get_current_pid_tgid() >> 32;
	cgroup_id = bpf_get_current_cgroup_id();
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
	struct cgroup_subsys_state *css = BPF_CORE_READ(ts, cgroups, subsys[bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id)]);
	struct cgroup *cgroup = BPF_CORE_READ(css, cgroup);
	struct mem_cgroup *mem_cgroup = (struct mem_cgroup *)(css - offsetof(struct mem_cgroup, css));
	long id = BPF_CORE_READ(cgroup, kn, id);


	struct lruvec lruvec = BPF_CORE_READ(mem_cgroup, nodeinfo[0], lruvec);
	struct list_head lru_active_anon_list = lruvec.lists[LRU_ACTIVE_ANON];
	struct list_head lru_inactive_anon_list = lruvec.lists[LRU_INACTIVE_ANON];
	struct list_head lru_active_file_list = lruvec.lists[LRU_ACTIVE_FILE];
	struct list_head lru_inactive_file_list = lruvec.lists[LRU_INACTIVE_FILE];

	print_lru_list(lru_active_anon_list);
	print_lru_list(lru_inactive_anon_list);
	print_lru_list(lru_active_file_list);
	print_lru_list(lru_inactive_file_list);

	return 0;
}
