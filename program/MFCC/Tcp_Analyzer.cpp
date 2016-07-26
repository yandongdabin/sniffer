#include "stdafx.h"
#include "Tcp_Analyzer.h"
#include "setting.h"
#include <map>
#include "Http_Module.h"
using namespace std;

map<CString,CString> Tcp_Analyzer::analysis_tranmission(u_char *pkt_data)
{
	map<CString,CString>result;
	ipv4_header *ih = (ipv4_header *)(pkt_data + 14);
	tcp_header *tp;
  u_int ip_len;
  u_short sport,dport;
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tp = (tcp_header *) ((u_char*)ih + ip_len);
	u_short flags = ntohs(tp->flags);
	int FIN = flags & 1;
	int SYN = (flags >> 1) & 1;
	int RST = (flags >> 2) & 1;
	int PSH = (flags >> 3) & 1;
	int ACK = (flags >> 4) & 1;
	int URG = (flags >> 5) & 1;
	sport = ntohs(tp->sport);
	dport = ntohs(tp->dport);

	int tcp_header_len = ((flags>>12)& 0x0F) *4;
	
	CString sourceIP;
	sourceIP.Format(_T("%d.%d.%d.%d:%d"),ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,sport);
	CString dstIP;
	dstIP.Format(_T("%d.%d.%d.%d:%d"),ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4,dport);
	CString fl;
	fl.Format(_T("ACK = %d SYN = %d URG = %d PSH = %d RST = %d FIN = %d"),ACK,SYN,URG,PSH,RST,FIN);
	result.insert(pair<CString,CString>(_T("源地址"),sourceIP));
	result.insert(pair<CString,CString>(_T("目的地址"),dstIP));
	result.insert(pair<CString,CString>(_T("标志位"),fl));

	u_char* tcp_ = (u_char *)(tp+tcp_header_len);

	map<CString,CString> user_result;//应用层数据
	if(sport == 80 || dport == 80){//HTTP协议
		Http_Module http;
		user_result = http.analysis(tcp_);

	}
	map<CString,CString>::iterator iter = user_result.begin();
	for(;iter!=user_result.end();iter++){
			result.insert(*iter);
	}
	return result;
}
