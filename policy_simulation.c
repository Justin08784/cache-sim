#include "policy_simulation.h"
#include <stdio.h>
#include <utlist.h>


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
	/*
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
	*/

	struct task_stats_entry *tse = NULL;
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

// We evict from the head of the list
void policy_simulation_evict(struct policy_simulation *ps, int num_to_evict) {
	printf("TODO: fix policy_simulation_evict\n");
	int size = policy_simulation_size(ps);
	printf("Size: %d, num_to_evict: %d\n", size, num_to_evict);
	if (num_to_evict >= size) return;
	while(num_to_evict--) {
		struct list_entry *del_entry = ps->list_head;
		DL_DELETE(ps->list_head, del_entry);
		if (del_entry->payload) {
			// WARNING: If payload points to a struct with other pointers in it that need to be freed, this will cause a memory leak
			free(del_entry->payload);
		}
		free(del_entry);
	}
}

int policy_simulation_size(struct policy_simulation *ps) {
	struct list_entry *entry;
	int size;
	DL_COUNT(ps->list_head, entry, size);
	return size;
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
	entry->payload = NULL;

	// Make entry the new head of the list
	DL_PREPEND(ps->list_head, entry);
}

int lfu_payload_cmp(void *left, void *right) {
	unsigned long l = *(unsigned long *)left;
	unsigned long r = *(unsigned long *)right;

	if (l < r) {
		return -1;
	} else if(l == r) {
		return 0;
	} else {
		return 1;
	}
}

void lfu_hit_update(struct policy_simulation *ps, struct list_entry *hit_entry) {
	*(unsigned long *)hit_entry->payload += 1;

	// Remove hit_entry from the list
	DL_DELETE(ps->list_head, hit_entry);

	struct list_entry *entry;
	DL_LOWER_BOUND(ps->list_head, entry, hit_entry, lfu_payload_cmp);

	// Make hit_entry the new head of the list
	DL_PREPEND(entry, hit_entry);
}

void lfu_miss_update(struct policy_simulation *ps, unsigned long folio) {
	struct list_entry *entry = (struct list_entry *)malloc(sizeof(struct list_entry));
	entry->folio = folio;
	entry->payload = malloc(sizeof(unsigned long));
	*(unsigned long *)entry->payload = 0;

	// Make entry the new head of the list
	DL_PREPEND(ps->list_head, entry);
}
