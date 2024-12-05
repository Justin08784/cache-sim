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

enum event_type {
    MPA,  // mark page access (read)
    MBD,  // mark buffer dirty (write)
    APCL, // access page clean (???)
    APD,  // access page dirty (???)
};

struct event {
    unsigned long folio_ptr;
    enum event_type etyp;
};



#endif /* PAGE_H */
