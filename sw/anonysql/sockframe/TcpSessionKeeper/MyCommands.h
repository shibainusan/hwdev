#pragma once
#include <stdint.h>

extern char remoteHostPort[1024];
extern uint8_t magicPacketDestMac[6];

extern bool DoMyCommand(const char* cmd);
