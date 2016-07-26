/*¼òµ¥¹¤³§*/

#include "stdafx.h"
#include "Factory.h"
#include "Analysis_Packet.h"
#include "Tcp_Analyzer.h"
#include "Udp_Analyzer.h"
#include "Icmp_Analyzer.h"
#include <map>

using namespace std;
std::map<int,std::map<CString,CString>> Factory::analysis(packet_Info &info)
{
	Analysis_Packet *analyzer;
	Protocol_Enum pro = info.pro;
	CString str;
	analyzer = new Analysis_Packet();
	switch(pro)
	{
	case UDP:
		analyzer = new Udp_Analyzer();
		break;
	case TCP:
		analyzer = new Tcp_Analyzer();
		break;
	case ICMP:
		analyzer = new Icmp_Analyzer();
		break;
	case IGMP:
		break;
	case OSPF:
		break;
	case IPV6:
		break;
	default:
		break;
	}
	
	return analyzer->analysis(info.info);
}