#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "map.h"

bool insert_map(map** self, const char* key, const char* value) {
  assert(self != NULL);
  assert(key != NULL);
  assert(value != NULL);

  map* item = malloc(sizeof(map));
  assert(item != NULL);
  item->key = key;
  item->value = value;

  if(find_map(*self, item->key) == NULL) {
    HASH_ADD_KEYPTR(hh, *self, item->key, strlen(item->key), item);
    return true;
  } else {
    return false;
  }
}

const char* find_map(map* self, const char* key) {
  assert(key != NULL);

  map* out = NULL;
  HASH_FIND_STR(self, key, out);
  return out == NULL ? NULL : out->value;
}

void iter_map(map* self, map_iter_func f) {
  map *each, *tmp;
  HASH_ITER(hh, self, each, tmp) {
    f(each->key, each->value);
  }
}

void clear_map(map** self) {
  HASH_CLEAR(hh, *self);
}
