/*
Copyright 2014 by Matthieu Boutier

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef ARRAY_H
#define ARRAY_H

#include <stdlib.h>

typedef int (*cmp_fun_t)(const void*, const void*);
typedef void (*free_fun_t)(void*);


struct array {
    int size;
    int num_elements;
    void *cell[1];
};

typedef struct array *array_t;
typedef int array_iter_t;

static inline array_t init_array(void) { return NULL; }
void free_array(array_t *array, free_fun_t free_fun);
int array_add(array_t *array, void *element, cmp_fun_t cmp_fun);
void *array_del(array_t array, void *element, cmp_fun_t cmp_fun);

static inline void init_iterator(array_iter_t *iter)
{
    *iter = 0;
}
void *get_next(array_t array, array_iter_t *iterator);

#endif /* ARRAY_H */
