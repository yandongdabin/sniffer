

/*用来处理包信息的接口 */
#pragma once
#include "stdafx.h"
#include "setting.h"
#include <map>
;
class Analysis_Packet{
public:
	std::map<int,std::map<CString,CString>> analysis(u_char *);
	std::map<CString,CString> analysis_physics(u_char *);
	std::map<CString,CString> analysis_datalink(u_char *);
	
	std::map<CString,CString> analysis_internet(u_char *);
	virtual std::map<CString,CString> analysis_tranmission(u_char *);
	virtual std::map<CString,CString> analysis_application(u_char *);
};