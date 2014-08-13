#ifndef _GETKCORE_H
#define _GETKCORE_H

typedef struct {
	unsigned int magic;
	unsigned int version;
	unsigned long long s_addr;
	unsigned long long e_addr;
	unsigned char reserved[8];
} __attribute__ ((__packed__)) lime_range;


#endif
