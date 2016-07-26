#pragma once
#include "stdafx.h"
#include "pcap.h"
#include "MFCCDlg.h"
#include "setting.h"
#include <vector>
#include "Factory.h"
#include <map>

using namespace std;
CString LAYER[5] = {_T("物理层"),_T("数据链路层"),_T("网络层"),_T("传输层(包含应用层协议)"),_T("应用层")};
/*此线程的目的是 将包的信息处理为十六进制和十进制的ASCII码的形式显示出来*/
UINT ThreadFunc1(LPVOID lpParam)
{
	thread_packet_info* info = (thread_packet_info *)lpParam;
	CMFCCDlg *dlg = (CMFCCDlg *)(info->dlg);
	packet_Info pac_info = info->info;
	CString result;
	CString result_hex;
	int j = 0;//计数指针
	for(size_t i=0;i< pac_info.len;i++){
		if(pac_info.info[i]>=32 && pac_info.info[i] <=126)//非控制字符
		{
			result.AppendFormat(_T("%c"),pac_info.info[i]);
		}
		else result += ".";

		result_hex.AppendFormat(_T("%02x  "),pac_info.info[i]);
		j++;
		if(j >= 16)
		{
			result += "\r\n";
			result_hex += "\r\n";
			j = 0;
		}
		else if(j == 8)
		{
			//result += "      ";
			//result_hex +="      ";
		}
	}
	result_hex.MakeUpper();
	(dlg->m_InfoText_).SetWindowTextW((LPCTSTR)result);
	(dlg->m_InfoText).SetWindowTextW((LPCTSTR)result_hex);

	Factory factory;
	std::map<int,std::map<CString,CString>> result_map = factory.analysis(pac_info);

	dlg-> m_InfoTree.DeleteAllItems();

	
	map<int,map<CString,CString>>::iterator iter = result_map.begin();
	HTREEITEM hRoot,hSubItem;

	for(;iter!=result_map.end();iter++)
	{
			//插入 层信息 如 “物理层”
			hRoot =dlg-> m_InfoTree.InsertItem((LPCTSTR)LAYER[iter->first],TVI_ROOT);
			map<CString,CString> tmp_map = iter->second;
			map<CString,CString>::iterator iter1 = tmp_map.begin();
			for(;iter1!=tmp_map.end();iter1++){
					hSubItem = dlg-> m_InfoTree.InsertItem((LPCTSTR)iter1->first,hRoot);
					dlg-> m_InfoTree.InsertItem((LPCTSTR)iter1->second,hSubItem);
			}

	}


	return 0;
}