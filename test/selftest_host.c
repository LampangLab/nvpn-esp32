#include <stdio.h>
#include <time.h>
#include "../examples/arduino/SelfTest/selftest_core.h"
static void lg(const char *s) { puts(s); }
static unsigned long us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (unsigned long)(t.tv_sec * 1000000UL + t.tv_nsec / 1000); }
int main(void) { st_t t = {lg, us, 0, 0}; return selftest_run(&t) ? 1 : 0; }
