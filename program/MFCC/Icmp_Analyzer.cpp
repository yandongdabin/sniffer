#include "StdAfx.h"
#include "Icmp_Analyzer.h"
#include <map>
using namespace std;
Icmp_Analyzer::Icmp_Analyzer(void)
{
}

Icmp_Analyzer::~Icmp_Analyzer(void)
{
}
map<CString,CString> Icmp_Analyzer::analysis_tranmission(u_char *pkt_data)
{
		map<CString,CString> result;
		ipv4_header *ih = (ipv4_header *)(pkt_data + 14);
		icmp_header *ich;
		u_int ip_len;
		ip_len = (ih->ver_ihl & 0xf) * 4;
		ich = (icmp_header *) ((u_char*)ih + ip_len);

		CString type;
		type.Format(_T("%d"),ich->type);
		CString code;
		code.Format(_T("%d"),ich->code);
		result.insert(pair<CString,CString>(_T("¿‡–Õ"),type));
		result.insert(pair<CString,CString>(_T("¥˙¬Î"),code));
		return result;
}

