#pragma once
#include "Arduino.h"
#define WL_CONNECTED 3
struct IPA{ std::string toString(){return "";} };
struct WiFiC{ void begin(const char*,const char*){} int status(){return 3;} IPA localIP(){return {};} int RSSI(){return 0;} }; static WiFiC WiFi;
