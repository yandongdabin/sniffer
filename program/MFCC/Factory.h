#pragma once
#include "stdafx.h"
#include "setting.h"
#include <map>
class Factory{
public:
	std::map<int,std::map<CString,CString>> analysis(packet_Info &);
	

};