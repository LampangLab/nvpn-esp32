#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#define HIGH 1
#define LOW 0
#define OUTPUT 1
inline void pinMode(int,int){} inline void digitalWrite(int,int){} inline unsigned long millis(){return 0;} inline void delay(unsigned){}
struct SerialC{ void begin(int){} void println(const char*s){ fprintf(stderr,"%s\n",s);} template<class... A> void printf(const char*f,A... a){ fprintf(stderr,f,a...);} } ; static SerialC Serial;
struct EspC{ unsigned getFreeHeap(){return 0;} }; static EspC ESP;
inline void configTime(long,int,const char*,const char*){}
