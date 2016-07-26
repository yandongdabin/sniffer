#ifndef SNIFFER_H
#define SNIFFER_H
#include "pcap.h"
#include <vector>
#include <string>
class CMFCCDlg;

class Sniffer
{
public:
	typedef unsigned long u_long;
	//char *iptos(u_long in);
	//char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
	//void ifprint(pcap_if_t *d);
	std::vector<CString> get_All_Devs();
	int open_Dev(char *name,CMFCCDlg *dlg);
	friend void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

protected:
	

private:
	pcap_t *dev_handle;//保存打开的链接

public:
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev_name[10][100];//记录设备的名字，用于打开设备
	bpf_u_int32 netmask[10];//记录各个设备的子网掩码，用于过滤数据包
	//CMFCCDlg *dlgHandle;

};
#endif

