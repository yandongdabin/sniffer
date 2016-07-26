#include "StdAfx.h"
#include "Udp_Analyzer.h"
#include <map>
using namespace std;

Udp_Analyzer::Udp_Analyzer(void)
{
}

Udp_Analyzer::~Udp_Analyzer(void)
{
}
map<CString,CString> Udp_Analyzer::analysis_tranmission(u_char *pkt_data)
{
		map<CString,CString>result;
		udp_header *uh;
		
		ipv4_header *ih = (ipv4_header *)(pkt_data + 14);
		u_int ip_len;
		u_short sport,dport,len;
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header *) ((u_char*)ih + ip_len);
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);
		len = ntohs(uh->len);


		CString sourceIP;
		sourceIP.Format(_T("%d.%d.%d.%d:%d"),ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,sport);
		CString dstIP;
		dstIP.Format(_T("%d.%d.%d.%d:%d"),ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4,dport);
		CString len_str;
		len_str.Format(_T("%d"),len);
		result.insert(pair<CString,CString>(_T("源地址"),sourceIP));
		result.insert(pair<CString,CString>(_T("目的地址"),dstIP));
		result.insert(pair<CString,CString>(_T("包长度"),len_str));
		return result;
}
