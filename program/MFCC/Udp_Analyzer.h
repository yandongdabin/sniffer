#pragma once
#include "analysis_packet.h"
#include <map>
class Udp_Analyzer : public Analysis_Packet
{
public:
		Udp_Analyzer(void);
		virtual ~Udp_Analyzer(void);
		virtual std::map<CString,CString> analysis_tranmission(u_char *data);
};
