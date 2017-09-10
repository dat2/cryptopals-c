#ifndef MAP_H
#define MAP_H

#include <uthash.h>

typedef struct {
  const char* key;
  const char* value;
  UT_hash_handle hh;
} map;

typedef void (*map_iter_func)(const char*, const char*);

bool insert_map(map** self, const char* key, const char* value);

const char* find_map(map* self, const char* key);

void iter_map(map* self, map_iter_func f);

void clear_map(map** self);

#endif
