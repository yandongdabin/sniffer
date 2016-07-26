#include "stdafx.h"
#include "Http_Module.h"
#include <map>
using namespace std;
map<CString,CString> Http_Module::analysis(u_char * data)//提供的是tcp数据的位置
{
		map<CString,CString> result;
		

		CString str;
		USES_CONVERSION;
		str.Format(_T("%s"),A2W((LPCSTR)data));
		//MessageBox(NULL,LPCTSTR(str),NULL,MB_OK);
		result.insert(pair<CString,CString>(_T("应用层协议"),_T("HTTP")));
		result.insert(pair<CString,CString>(_T("数据"),str));
		return result;
}