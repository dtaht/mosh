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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "util.h"
#include "array.h"

#define MIN_SIZE (8 * sizeof(void *))
#define RESIZE(array, newsize)                                  \
    (sizeof(*(array)) + ((newsize) - 1) * sizeof(void *))


/* return the index of element in array, if it exists, and
   (-1 - i) otherwise, with i the index where it should be. */
static int
array_search(array_t array, void *element, cmp_fun_t cmp_fun)
{
    void **cell = array->cell;
    int b = 0, e = array->num_elements - 1, m, cmp;

    while (b <= e) {
        m = (b + e) / 2;
        cmp = cmp_fun(element, cell[m]);
        if (cmp < 0)
            e = m - 1;
        else if (cmp > 0)
            b = m + 1;
        else
            return m;
    }

    return -b - 1;
}

int
array_add(array_t *array, void *element, cmp_fun_t cmp_fun)
{
    array_t arr = *array;
    void **cell;
    int i;

    if (UNLIKELY(!arr) || arr->size <= arr->num_elements) {
        array_t tmp;
        int size = arr ? 2 * arr->size : MIN_SIZE;
        tmp = realloc(arr, RESIZE(arr, size));
        if (!tmp) return -1;
        *array = tmp;
        arr = tmp;
        tmp->size = size;
    }

    i = array_search(arr, element, cmp_fun);
    if (i >= 0) {
        errno = EEXIST;
        return -1;
    }

    i = -i - 1;
    cell = arr->cell;
    assert(0 <= i && i <= arr->num_elements && i < arr->size);
    if (i < arr->num_elements)
        memmove(&cell[i + 1], &cell[i],
                (arr->num_elements - i) * sizeof(void *));
    cell[i] = element;
    arr->num_elements++;
    return 0;
}

void *
array_del(array_t array, void *element, cmp_fun_t cmp_fun)
{
    void **cell;
    void *result;
    int i;

    if (!array) goto not_found;
    i = array_search(array, element, cmp_fun);
    if (i < 0) goto not_found;

    cell = array->cell;
    result = cell[i];
    array->num_elements --;
    if (i < array->num_elements)
        memmove(&cell[i], &cell[i + 1],
                (array->num_elements - i) * sizeof(void *));
    if (array->num_elements < array->size / 4 && array->size > MIN_SIZE) {
        array_t tmp;
        tmp = realloc(array, RESIZE(array, array->size / 2));
        assert(tmp && tmp == array);
        assert(array->size >= MIN_SIZE);
    }
    return result;
 not_found:
    errno = EEXIST;
    return NULL;
}

void
free_array(array_t *array, free_fun_t free_fun)
{
    array_t arr = *array;
    int i;
    if (!arr) return;
    for (i = 0; i < arr->num_elements; i ++)
        free_fun(arr->cell[i]);
    free(arr);
    *array = NULL;
}

void *
get_next(array_t array, array_iter_t *iter)
{
    const int i = *iter;
    if (!array || i >= array->num_elements)
        return NULL;
    ++*iter;
    return array->cell[i];
}
