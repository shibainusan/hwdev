#include <string>
#include <vector>

#include "utils.h"

extern "C" {
#include "MyCommands.h"
extern void SendMagicPacketOnAllLocalIP(const uint8_t destMac[6]);
}

char remoteHostPort[1024] = { 0 };
uint8_t magicPacketDestMac[6] = { 0 };
/*
' TcpSessionKeeper commands
K, , "RemoteHostPort 192.168.0.20:56001"
K, , "SendMagicPacket 00-00-91-09-85-40"
*/

extern bool DoMyCommand(const char* cmd)
{
	bool ret = false;
	T_STRING_LIST tokens;
	std::string line(cmd);

	SplitString(&tokens, line, " \t");
	if (tokens.empty()) {
		return false; //no token.
	}

	if (0 == tokens.front().compare("RemoteHostPort")) {
		tokens.pop_front();
		strcpy_s(remoteHostPort, sizeof(remoteHostPort), tokens.front().c_str());
		ret = true;
	}
	else if (0 == tokens.front().compare("SendMagicPacket")) {
		tokens.pop_front();
		MacAddrStringToCharArray(tokens.front().c_str(), magicPacketDestMac, sizeof(magicPacketDestMac));
		SendMagicPacketOnAllLocalIP(magicPacketDestMac);
		ret = true;
	}
	else {
		//not my command.
	}
	return ret;

}