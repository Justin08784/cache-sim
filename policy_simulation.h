#ifndef POLICY_SIMULATION_H
#define POLICY_SIMULATION_H

#include <uthash.h>
#include "common.h"


struct list_entry {
	struct list_entry *prev;
	struct list_entry *next;
	unsigned long folio;
	void *payload;
};

struct task_stats_entry {
	struct task_key key;
	unsigned long hits;
	unsigned long misses;
	UT_hash_handle hh;
};

struct policy_simulation {
	struct list_entry *list_head;
	struct task_stats_entry *task_stats;
	void (*hit_update)(struct policy_simulation *, struct list_entry *);
	void (*miss_update)(struct policy_simulation *, unsigned long);
	unsigned long hits;
	unsigned long misses;
};


struct policy_simulation *policy_simulation_init(void (*hit_update)(struct policy_simulation *, struct list_entry *), void (*miss_update)(struct policy_simulation *, unsigned long));
void policy_simulation_track_access(struct policy_simulation *ps, const struct event *e);
void policy_simulation_evict(struct policy_simulation *ps, unsigned long num_to_evict);
int policy_simulation_size(struct policy_simulation *ps);
void policy_simulation_print(struct policy_simulation *ps);
void mru_hit_update(struct policy_simulation *ps, struct list_entry *hit_entry);
void mru_miss_update(struct policy_simulation *ps, unsigned long folio);
void lfu_hit_update(struct policy_simulation *ps, struct list_entry *hit_entry);
void lfu_miss_update(struct policy_simulation *ps, unsigned long folio);

#endif
