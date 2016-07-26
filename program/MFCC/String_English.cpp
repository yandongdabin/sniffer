#include "StdAfx.h"
#include "String_English.h"

String_English::String_English(void)
{
		GRAMMER_ERROR = _T("grammer error");
		STIIL_SCAN_ERROR = _T("still scanning");
		FAIL_TO_FILTER = _T("filter error");
		ALREADY_SCAN = _T("alreay scaning");
		SAVE_ERROR = _T("save error");
		OPEN_ERROR = _T("open file error");
		NULL_OPEN = _T("please select one adapter or file to open first");
		FAIL_TO_GET_ADAPTER = _T("fail to get the adapter list");
		FILTERING = _T("filtering");
		NOT_DATA = _T("stop scaning first");
}

String_English::~String_English(void)
{
}
