#pragma once
#include "Arduino.h"
typedef enum { WStype_ERROR, WStype_DISCONNECTED, WStype_CONNECTED, WStype_TEXT, WStype_BIN } WStype_t;
struct WebSocketsClient{ void beginSSL(const char*,unsigned short,const char*){} void onEvent(void(*)(WStype_t,uint8_t*,size_t)){} void setReconnectInterval(unsigned){} void enableHeartbeat(unsigned,unsigned,unsigned){} void loop(){} bool isConnected(){return true;} bool sendTXT(const char*m){ printf("SEND %s\n", m); fflush(stdout); return true;} };
