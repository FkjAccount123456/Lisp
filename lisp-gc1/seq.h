#include <stdlib.h>

#define Extend(type, size, max, ptr)                                           \
  if (size == max) {                                                           \
    max *= 2;                                                                  \
    ptr = (type *)realloc(ptr, sizeof(type) * max);                            \
  }

// Extendable sequence

#define NewSeq(type, name)                                                     \
  size_t name##_max = 8, name##_size = 0;                                      \
  type *name##_val = (type *)malloc(sizeof(type) * name##_max)

#define FreeSeq(name) free(name##_val)

#define SeqNth(name, n) (name##_val[n])

#define SeqAppend(type, name, val)                                             \
  Extend(type, name##_size, name##_max, name##_val);                           \
  name##_val[name##_size++] = val

#define SeqSize(name) (name##_size)

#define SeqPop(name) (name##_val[--name##_size])