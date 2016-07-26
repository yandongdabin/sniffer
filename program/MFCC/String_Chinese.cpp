#include "stdafx.h"
#include "String_Chinese.h"
String_Chinese::String_Chinese()
{
		GRAMMER_ERROR = _T("语法错误");
		STIIL_SCAN_ERROR = _T("仍然在扫描");
		FAIL_TO_FILTER = _T("过滤失败");
		ALREADY_SCAN = _T("已经开始扫描了");
		SAVE_ERROR = _T("保存失败");
		OPEN_ERROR = _T("文件打开失败");
		NULL_OPEN = _T("请先选择一个适配器或打开的文件");
		FAIL_TO_GET_ADAPTER = _T("获得适配器列表失败");
		FILTERING = _T("过滤中");
		NOT_DATA = _T("等待扫描结束");
}
