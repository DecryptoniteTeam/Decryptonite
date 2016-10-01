// Based off: http://stackoverflow.com/questions/3536153/c-dynamically-growing-array

#include "array.h"

// Intializes an array with specfied size, meant to hold type struct PidChangeTracker
void InitalizeArray(Array *a, size_t initialSize) {
	a->array = (struct PidChangeTracker *)malloc(initialSize * sizeof(struct PidChangeTracker));
	if (a->array == NULL) {
		fprintf(stderr, "Failed to create array.");
		exit(EXIT_FAILURE);
	}
	a->used = 0;
	a->size = initialSize;
}

// Insert a new element of type struct PidChangeTracker, and expands the array size when it is full
void InsertElement(Array *a, struct PidChangeTracker *pTracker) {
	if (a->used == a->size) {
		a->size *= 2;
		a->array = (struct PidChangeTracker *)realloc(a->array, a->size * sizeof(struct PidChangeTracker));
		if (a->array == NULL) {
			fprintf(stderr, "Failed to expand size of array.");
			exit(EXIT_FAILURE);
		}
	}
	a->array[a->used++] = *pTracker;
}

// Clean up all the memory used for the array once it's no longer needed
void FreeArray(Array *a) {
	free(a->array);
	a->array = NULL;
	a->used = a->size = 0;
	if (a->array != NULL) {
		fprintf(stderr, "Failed to free up array.");
		exit(EXIT_FAILURE);
	}
}