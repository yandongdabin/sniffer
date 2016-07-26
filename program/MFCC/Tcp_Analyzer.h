#pragma once
#include "stdafx.h"
#include "Analysis_Packet.h"
#include <map>
class Tcp_Analyzer:public Analysis_Packet
{
public:
	virtual std::map<CString,CString> analysis_tranmission(u_char *data);
};