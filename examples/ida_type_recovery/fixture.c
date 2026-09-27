#include <stdint.h>
#include <stdio.h>
typedef int (*method)(void *, int);
__attribute__((noinline)) int add(void *obj, int x) { return *(int *)((char *)obj + 8) + x; }
__attribute__((noinline)) int sub(void *obj, int x) { return *(int *)((char *)obj + 8) - x; }
__attribute__((noinline)) int dispatch(void *obj, int x) {
    uintptr_t vt = *(uintptr_t *)obj;
    int first = ((method)*(uintptr_t *)vt)(obj, x);
    return first + ((method)*(uintptr_t *)(vt + 8))(obj, x + 1);
}
int main(int argc, char **argv) {
    method slots[] = { add, sub };
    struct { method *vt; int value; } object = { slots, argc };
    printf("%d\n", dispatch(&object, argc));
    return argv == 0;
}
