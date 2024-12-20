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
	if (e->type == SFL) {
		policy_simulation_evict(ps, e->num_evicted);
		return;
	}

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
void policy_simulation_evict(struct policy_simulation *ps, unsigned long num_to_evict) {
	int size = policy_simulation_size(ps);
	if (num_to_evict >= size) return;

	while(num_to_evict--) {
		struct list_entry *del_entry = ps->list_head;
		DL_DELETE(ps->list_head, del_entry);
		if (del_entry && del_entry->payload) {
			// WARNING: If payload points to a struct with other pointers in it that need to be freed, this will cause a memory leak
            // Future work: have user provide a cleanup function for the payload, call it on payload and set payload to NULL
			free(del_entry->payload);
		}
		free(del_entry);
	}
}

float policy_simulation_total_hit_percent(struct policy_simulation *ps) {
	if (ps->hits + ps->misses > 0) {
		return 100.0 * ((float)ps->hits / (float)(ps->hits + ps->misses));
	} else {
		return -1;
	}
}

float policy_simulation_task_hit_percent(struct policy_simulation *ps, const struct task_key *key) {
	struct task_stats_entry *tse = NULL;
    assert(ps);
    assert(key);
	HASH_FIND(hh, ps->task_stats, key, sizeof(struct task_key), tse);
	if (tse) {
		return 100.0 * ((float)tse->hits / (float)(tse->hits + tse->misses));
	} else {
		return -1;
	}
}

int policy_simulation_size(struct policy_simulation *ps) {
    assert(ps);
	struct list_entry *entry;
	int size;
	DL_COUNT(ps->list_head, entry, size);
	return size;
}

void policy_simulation_print(struct policy_simulation *ps) {
    assert(ps);
	struct list_entry *entry = NULL;
	int position = 0;
	DL_FOREACH(ps->list_head, entry) {
        if(entry) printf("Position: %d, Folio: %lu\n", position++, entry->folio);
		//printf("Position: %d, Folio: %lu, Payload: %lu\n", position++, entry->folio, *(unsigned long *)entry->payload);
	}

	printf("Size: %d, Hits: %lu, Misses: %lu\n", policy_simulation_size(ps), ps->hits, ps->misses);
}

void fifo_hit_update(struct policy_simulation *ps, struct list_entry *hit_entry) {
	// Do nothing on hit
	return;
}

void fifo_miss_update(struct policy_simulation *ps, unsigned long folio) {
	struct list_entry *entry = (struct list_entry *)malloc(sizeof(struct list_entry));
	entry->folio = folio;
	entry->payload = NULL;

	// Make entry the new tail of the list
	DL_APPEND(ps->list_head, entry);
}

int lfu_payload_cmp(struct list_entry *left, struct list_entry *right) {
	unsigned long l = *(unsigned long *)left->payload;
	unsigned long r = *(unsigned long *)right->payload;

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

	// Insert hit_entry in sorted order
	DL_INSERT_INORDER(ps->list_head, hit_entry, lfu_payload_cmp);
}

void lfu_miss_update(struct policy_simulation *ps, unsigned long folio) {
	struct list_entry *entry = (struct list_entry *)malloc(sizeof(struct list_entry));
	entry->folio = folio;
	entry->payload = malloc(sizeof(unsigned long));
	*(unsigned long *)entry->payload = 0;

	// Make entry the new head of the list
	DL_PREPEND(ps->list_head, entry);
}

void lru_hit_update(struct policy_simulation *ps, struct list_entry *hit_entry) {
	// Remove hit_entry from the list
	DL_DELETE(ps->list_head, hit_entry);
	// Make hit_entry the new tail of the list
	DL_APPEND(ps->list_head, hit_entry);
}

void lru_miss_update(struct policy_simulation *ps, unsigned long folio) {
	struct list_entry *entry = (struct list_entry *)malloc(sizeof(struct list_entry));
	entry->folio = folio;
	entry->payload = NULL;

	// Make entry the new tail of the list
	DL_APPEND(ps->list_head, entry);
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
