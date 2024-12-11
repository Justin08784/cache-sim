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


int main() {
	FILE *log_file = fopen("page.log", "r");
	if (!log_file) {
		printf("Failed to open log file\n");
		return 0;
	}

	struct policy_simulation *ps = policy_simulation_init(&lfu_hit_update, &lfu_miss_update);

	struct linux_task_stats_entry *linux_task_stats = NULL;
	unsigned long fma, faf, fmd, mbd;
	fma = faf = fmd = mbd = 0;

	struct event e;
	char type_str[16];
	while (fscanf(log_file, "%lu,%d,%d,%d,%[^\n]s\n", &e.folio, (int*)&e.type, &e.key.uid, &e.key.pid, e.key.command) == 5) {
		switch (e.type) {
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

		switch (e.type) {
			case SFL:
				printf("UID: %d | PID: %d | COMMAND: %s | TYPE: %s | NUM_EVICTED: %lu\n", e.key.uid, e.key.pid, e.key.command, type_str, e.folio);
				break;
			default:
				printf("UID: %d | PID: %d | COMMAND: %s | TYPE: %s | FOLIO: %lu\n", e.key.uid, e.key.pid, e.key.command, type_str, e.folio);
				break;
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
		if (e.type == SFL) {
			policy_simulation_evict(ps, e.num_evicted);
		} else {
			policy_simulation_track_access(ps, &e);
		}
		policy_simulation_print(ps);
	}

	fclose(log_file);

	struct linux_task_stats_entry *ltse = NULL;
	struct task_stats_entry *tse = NULL;
	struct linux_task_stats_entry *tmp = NULL;
	printf("\n");
	printf("%-16s    %-16s    %-16s    %-16s\n", "Command", "Real Hit %", "Sim Hit %", "Hits + Misses");
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

		struct task_key key = ltse->key;
		HASH_FIND(hh, ps->task_stats, &key, sizeof(struct task_key), tse);
		float sim_hit_percent = 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));

		//if (p->value.real_hits + p->value.sim_hits > 100) {
		if (total > 0)
			printf("%-16s    %-16.2f    %-16.2f    %-16.2f\n", tse->key.command, real_hit_percent, sim_hit_percent, total);
	}
}
