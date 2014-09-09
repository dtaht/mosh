#ifndef TOTO
#define TOTO
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
extern FILE *pok;
static inline void dbg(char *str) {
    fprintf(pok, str);
    fflush(pok);
}
#endif
