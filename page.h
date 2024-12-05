#ifndef PAGE_H
#define PAGE_H

struct list_entry {
	struct list_entry *next;
        struct list_entry *prev;
	unsigned long pfn;
};

struct list {
	struct list_entry *head;
	struct list_entry *tail;
	int hits;
	int misses;
};

struct event {
    uint32_t key;
    uint32_t value;
};

#endif /* PAGE_H */
