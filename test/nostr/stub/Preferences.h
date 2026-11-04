#pragma once
#include "Arduino.h"
struct Preferences{ void begin(const char*,bool){} size_t getBytes(const char*,void*,size_t){return 0;} size_t putBytes(const char*,const void*,size_t){return 0;} void end(){} };
