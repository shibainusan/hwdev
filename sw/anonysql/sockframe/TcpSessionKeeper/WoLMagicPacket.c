#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <Winsock2.h>

static void DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Šù’è‚ÌŒ¾Œê
		(LPTSTR)&lpMsgBuf, 0, NULL);
	printf("WSAERR:%s\n", lpMsgBuf);
	LocalFree(lpMsgBuf);
}

bool SendMagicPacket(const char destMac[6], uint32_t localAddr)
{
	SOCKET s = socket(PF_INET, SOCK_DGRAM, 0);
	int yes = 1;
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = localAddr;
	sa.sin_port = 0; //any local UDP port.
	int ret = bind(s, (const struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		DispLastError();
		closesocket(s);
		return false;
	}

	const char seq[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
	char pkt[17 * 6];
	char* p = pkt;
	memcpy(p, seq, sizeof(seq));
	p += sizeof(seq);
	int i;
	for (i = 0; i < 16; i++) {
		memcpy(p, destMac, 6);
		p += 6;
	}

	sa.sin_addr.S_un.S_addr = 0xFFFFFFFF; //local broadcast
	sa.sin_port = htons(9); //dest UDP port
	ret = sendto(s, pkt, sizeof(pkt), 0, (const struct sockaddr*)&sa, sizeof(sa));
	if (ret != sizeof(pkt)) {
		DispLastError();
		closesocket(s);
		return false;
	}
	closesocket(s);
	return true;

}

extern void SendMagicPacketOnAllLocalIP(const uint8_t destMac[6])
{
	char name[1024];
	struct hostent* hs;
	uint32_t  addr;
	int i;

	gethostname(name, sizeof(name));
	hs = gethostbyname(name);

	for (i = 0; NULL != hs->h_addr_list[i]; i++) {
		addr = *(uint32_t*)hs->h_addr_list[i];
		SendMagicPacket(destMac, addr);
	}
}