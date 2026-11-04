#pragma once
#include "Arduino.h"
#include <sys/random.h>
inline void esp_fill_random(void*p,size_t n){ getrandom(p,n,0); }
