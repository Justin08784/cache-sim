#include <stdio.h>
#include <string.h>
#include "common.h"
#include "policy_simulation.h"


struct linux_task_stats_entry {
	struct task_key key;
	unsigned long fma;
	unsigned long faf;
	unsigned long fmd;
	unsigned long mbd;
	UT_hash_handle hh;
};


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


int main() {
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
	while (fscanf(log_file, "%lu,%d,%d,%d,%[^\n]s\n", &e.data, (int *)&e.type, &e.key.uid, &e.key.pid, e.key.command) == 5) {
		event_print(&e);

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
				fma++;
				ltse->fma++;
				break;
			case FAF:
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
	//HASH_ITER(hh, ps->task_stats, tse, tmp) {
	HASH_ITER(hh, linux_task_stats, ltse, tmp) {
		/*
		unsigned long total = ltse->fma + ltse->faf + ltse->fmd + ltse->mbd;
		float real_hit_percent = 100.0 * ((float)(ltse->fma + ltse->faf) / (float)(total));
		*/
		float total = (float)ltse->fma - (float)ltse->mbd;
		float misses = (float)ltse->faf - (float)ltse->fmd;
		if (misses < 0)
			misses = 0;
		if (total < 0)
			total = 0;
		float hits = total - misses;
		if (hits < 0) {
			misses = total;
			hits = 0;
		}
		float real_hit_percent = 100.0 * (hits / total);
		//float real_hit_percent = 100.0 * (hits / accesses);
		//float real_hit_percent = 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));

		float fifo_hit_percent = policy_simulation_calculate_hit_percent(fifo_ps, &ltse->key);
		float lfu_hit_percent = policy_simulation_calculate_hit_percent(lfu_ps, &ltse->key);
		float lru_hit_percent = policy_simulation_calculate_hit_percent(lru_ps, &ltse->key);
		float mru_hit_percent = policy_simulation_calculate_hit_percent(mru_ps, &ltse->key);

		//if (p->value.real_hits + p->value.sim_hits > 100) {
		if (total > 0) {
			printf("%-16s    ", ltse->key.command);
			printf("%-16.2f    ", real_hit_percent);
			printf("%-16.2f    ", fifo_hit_percent);
			printf("%-16.2f    ", lfu_hit_percent);
			printf("%-16.2f    ", lru_hit_percent);
			printf("%-16.2f    ", mru_hit_percent);
			printf("%-16.2f\n", total);
		}
	}
}
