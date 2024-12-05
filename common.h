#ifndef COMMON_H
#define COMMON_H

enum access_type {
	FMA,
	FAF,
	TEMP,
	MBD,
};

struct top_key {
	unsigned int pid;
	unsigned int uid;
	char command[16];
};

struct value {
	unsigned long real_hits;
	unsigned long real_misses;
	unsigned long sim_hits;
	unsigned long sim_misses;
};

struct event {
	unsigned long folio;
	enum access_type type;
	struct top_key key;
};

#endif
