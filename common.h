#ifndef COMMON_H
#define COMMON_H

enum access_type {
	FMA,
	FAF,
	FMD,
	MBD,
	SFL,
};

struct task_key {
	unsigned int uid;
	unsigned int pid;
	char command[16];
};

struct event {
	union {
		unsigned long folio;
		unsigned long num_evicted;
	};
	enum access_type type;
	struct task_key key;
};

#endif
