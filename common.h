#ifndef COMMON_H
#define COMMON_H

enum access_type {
	FMA,
	FAF,
	TEMP,
	MBD,
};

struct event {
	unsigned long folio;
	enum access_type type;
};

#endif
