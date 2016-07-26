#pragma once
#include "analysis_packet.h"
#include <map>
class Icmp_Analyzer :public Analysis_Packet
{
public:
		Icmp_Analyzer(void);
		virtual ~Icmp_Analyzer(void);
		virtual std::map<CString,CString> analysis_tranmission(u_char *data);
};
