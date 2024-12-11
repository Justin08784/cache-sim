#include <stdio.h>
#include <string.h>
#include "common.h"
#include "policy_simulation.h"


int main() {
	FILE *log_file = fopen("page.log", "r");
	if (!log_file) {
		printf("Failed to open log file\n");
		return 0;
	}

	struct policy_simulation *ps = policy_simulation_init(&lfu_hit_update, &lfu_miss_update);

	struct event e;
	char type_str[16];
	while (fscanf(log_file, "%lu,%d,%d,%d,%[^\n]s\n", &e.folio, (int*)&e.type, &e.key.uid, &e.key.pid, e.key.command) == 5) { // TODO
		switch (e.type) {
			case FMA:
				strcpy(type_str, "FMA");
				break;
			case FAF:
				strcpy(type_str, "FAF");
				break;
			case TEMP:
				strcpy(type_str, "TEMP");
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


		if (e.type == SFL) {
			policy_simulation_evict(ps, e.num_evicted);
		} else {
			policy_simulation_track_access(ps, &e);
		}
		policy_simulation_print(ps);
	}

	fclose(log_file);

	struct task_stats_entry *tse = NULL;
	struct task_stats_entry *tmp = NULL;
	printf("\n");
	printf("%-16s    %-16s    %-16s\n", "Command", "Real Hit %", "Sim Hit %");
	//HASH_ITER(hh, linux_task_stats, tse, tmp) {
	HASH_ITER(hh, ps->task_stats, tse, tmp) {
		float real_hit_percent = 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));

		struct task_key key = tse->key;
		HASH_FIND(hh, ps->task_stats, &key, sizeof(struct task_key), tse);
		float sim_hit_percent = 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));

		//if (p->value.real_hits + p->value.sim_hits > 100) {
		printf("%-16s    %-16.2f    %-16.2f\n", tse->key.command, real_hit_percent, sim_hit_percent);
	}
}
