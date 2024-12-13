#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <math.h>
#include "common.h"
#include "policy_simulation.h"


struct simulator_opts {
	bool p;
	bool s;
};


struct linux_task_stats_entry {
	struct task_key key;
	unsigned long fma;
	unsigned long faf;
	unsigned long fmd;
	unsigned long mbd;
	UT_hash_handle hh;
};


float calculate_linux_hit_percent(unsigned long fma, unsigned long faf, unsigned long fmd, unsigned long mbd) {
	// total = total cache accesses without counting dirties
	// misses = total of add to lru because of read misses
	float total = (float)fma - (float)mbd;
	float misses = (float)faf - (float)fmd;
	if (misses < 0)
		misses = 0;
	if (total < 0)
		total = 0;
	float hits = total - misses;
	if (hits < 0) {
		misses = total;
		hits = 0;
	}
	return 100.0 * (hits / total);
}


void event_print(struct event *e) {
	char type_str[16];
	switch (e->type) {
		case FMA:
			strcpy(type_str, "FMA");
			break;
		case FAF:
			strcpy(type_str, "FAF");
			break;
		case FMD:
			strcpy(type_str, "FMD");
			break;
		case MBD:
			strcpy(type_str, "MBD");
			break;
		case SFL:
			strcpy(type_str, "SFL");
			break;
	}

	switch (e->type) {
		case SFL:
			printf("UID: %8d | PID: %8d | COMMAND: %16s | TYPE: %s | NUM_EVICTED: %lu\n", e->key.uid, e->key.pid, e->key.command, type_str, e->num_evicted);
			break;
		default:
			printf("UID: %8d | PID: %8d | COMMAND: %16s | TYPE: %s | FOLIO: %lu\n", e->key.uid, e->key.pid, e->key.command, type_str, e->folio);
			break;
	}
}


int main(int argc, char **argv) {
	struct simulator_opts flags;
	flags.p = false;
	flags.s = false;
	int opt;
	while ((opt = getopt(argc, argv, "ps")) != -1) {
		switch(opt) {
			case 'p':
				flags.p = true;
				break;
			case 's':
				flags.s = true;
				break;
			case '?':
				printf("Usage: %s [-p] [-s]\n", argv[0]);
				printf("-p: Print events\n");
				printf("-s: Simulate evictions\n");
				return 1;
				break;
		}
	}


	FILE *log_file = fopen("page.log", "r");
	if (!log_file) {
		printf("Failed to open log file\n");
		return 0;
	}

	struct policy_simulation *fifo_ps = policy_simulation_init(&fifo_hit_update, &fifo_miss_update);
	struct policy_simulation *lfu_ps = policy_simulation_init(&lfu_hit_update, &lfu_miss_update);
	struct policy_simulation *lru_ps = policy_simulation_init(&lru_hit_update, &lru_miss_update);
	struct policy_simulation *mru_ps = policy_simulation_init(&mru_hit_update, &mru_miss_update);

	struct linux_task_stats_entry *linux_task_stats = NULL;
	unsigned long fma, faf, fmd, mbd;
	fma = faf = fmd = mbd = 0;

	struct event e;
	unsigned long event_count = 0;
	while (fscanf(log_file, "%lu,%d,%d,%d,%[^\n]s\n", &e.data, (int *)&e.type, &e.key.uid, &e.key.pid, e.key.command) == 5) {
		event_count++;
		if (flags.s && event_count % 100 == 0) {
			unsigned long num_evicted = 10;
			policy_simulation_evict(fifo_ps, num_evicted);
			policy_simulation_evict(lfu_ps, num_evicted);
			policy_simulation_evict(lru_ps, num_evicted);
			policy_simulation_evict(mru_ps, num_evicted);
		}
		if (flags.p) {
			event_print(&e);
		}

		struct linux_task_stats_entry *ltse = NULL;
		HASH_FIND(hh, linux_task_stats, &e.key, sizeof(struct task_key), ltse);
		if (!ltse && e.type != SFL) {
			ltse = (struct linux_task_stats_entry *)malloc(sizeof(struct linux_task_stats_entry));
			ltse->key = e.key;
			ltse->fma = 0;
			ltse->faf = 0;
			ltse->fmd = 0;
			ltse->mbd = 0;
			HASH_ADD(hh, linux_task_stats, key, sizeof(struct task_key), ltse);
		}
		switch (e.type) {
			case FMA:
                // folio mark accessed ()
				fma++;
				ltse->fma++;
				break;
			case FAF:
                // filemap add folio (miss)
				faf++;
				ltse->faf++;
				break;
			case FMD:
				fmd++;
				ltse->fmd++;
				break;
			case MBD:
				mbd++;
				ltse->mbd++;
				break;
			default:
				break;
		}

		policy_simulation_track_access(fifo_ps, &e);
		policy_simulation_track_access(lfu_ps, &e);
		policy_simulation_track_access(lru_ps, &e);
		policy_simulation_track_access(mru_ps, &e);
	}

	fclose(log_file);

	struct linux_task_stats_entry *ltse = NULL;
	struct linux_task_stats_entry *tmp = NULL;
	printf("\n");
	printf("%-16s    ", "Command");
	printf("%-16s    ", "Real Hit %");
	printf("%-16s    ", "FIFO Hit %");
	printf("%-16s    ", "LFU Hit %");
	printf("%-16s    ", "LRU Hit %");
	printf("%-16s    ", "MRU Hit %");
	printf("%-16s\n", "Hits + Misses");

	float real_hit_percent, fifo_hit_percent, lfu_hit_percent, lru_hit_percent, mru_hit_percent;
	real_hit_percent = calculate_linux_hit_percent(fma, faf, fmd, mbd);
	fifo_hit_percent = policy_simulation_total_hit_percent(fifo_ps);
	lfu_hit_percent = policy_simulation_total_hit_percent(lfu_ps);
	lru_hit_percent = policy_simulation_total_hit_percent(lru_ps);
	mru_hit_percent = policy_simulation_total_hit_percent(mru_ps);
	printf("%-16s    ", "TOTAL");
	printf("%-16.2f    ", real_hit_percent);
	printf("%-16.2f    ", fifo_hit_percent);
	printf("%-16.2f    ", lfu_hit_percent);
	printf("%-16.2f    ", lru_hit_percent);
	printf("%-16.2f    ", mru_hit_percent);
	printf("%-16lu\n", fifo_ps->hits + fifo_ps->misses);

	HASH_ITER(hh, linux_task_stats, ltse, tmp) {
		real_hit_percent = calculate_linux_hit_percent(ltse->fma, ltse->faf, ltse->fmd, ltse->mbd);

		fifo_hit_percent = policy_simulation_task_hit_percent(fifo_ps, &ltse->key);
		lfu_hit_percent = policy_simulation_task_hit_percent(lfu_ps, &ltse->key);
		lru_hit_percent = policy_simulation_task_hit_percent(lru_ps, &ltse->key);
		mru_hit_percent = policy_simulation_task_hit_percent(mru_ps, &ltse->key);


		if (!isnan(real_hit_percent)) {
			struct task_stats_entry *tse = NULL;
			HASH_FIND(hh, fifo_ps->task_stats, &ltse->key, sizeof(struct task_key), tse);
			printf("%-16s    ", ltse->key.command);
			printf("%-16.2f    ", real_hit_percent);
			printf("%-16.2f    ", fifo_hit_percent);
			printf("%-16.2f    ", lfu_hit_percent);
			printf("%-16.2f    ", lru_hit_percent);
			printf("%-16.2f    ", mru_hit_percent);
			printf("%-16lu\n", tse->hits + tse->misses);
		}
	}
}
