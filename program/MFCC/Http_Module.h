#pragma once
#include "stdafx.h"
#include <map>
class Http_Module{
public:
		std::map<CString,CString> analysis(u_char *);//提供的是tcp数据包的包头
};