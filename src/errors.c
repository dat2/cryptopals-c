#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

#include "errors.h"

void print_stack_trace() {
  void* callstack[128];
  int frames = backtrace(callstack, 128);
  char** strs = backtrace_symbols(callstack, frames);
  for (int i = 0; i < frames; ++i) {
    printf("%s\n", strs[i]);
  }
  free(strs);
}
