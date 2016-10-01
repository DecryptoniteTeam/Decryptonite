//#pragma once
// Header file for the queue

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <winioctl.h>
#include <time.h>
#include "utarray.h"

typedef struct {
	struct PidChangeTracker *array;
	size_t used;
	size_t size;
} Array;

struct PidChangeTracker {
	int pid;
	int size;
	int checks;
	float writesPerSec;
	int isHigh;
	int isMedium;
	int isLow;
	UT_array *queue;
};

void InitalizeArray(Array *a, size_t initialSize);
void InsertElement(Array *a, struct PidChangeTracker *pTracker);
void FreeArray(Array *a);