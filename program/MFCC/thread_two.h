#pragma once
#include "stdafx.h"
#include "pcap.h"
#include "MFCCDlg.h"
#include "setting.h"
#include <vector>
#include "Factory.h"
#include <map>

using namespace std;
CString LAYER[5] = {_T("�����"),_T("������·��"),_T("�����"),_T("�����(����Ӧ�ò�Э��)"),_T("Ӧ�ò�")};
/*���̵߳�Ŀ���� ��������Ϣ����Ϊʮ�����ƺ�ʮ���Ƶ�ASCII�����ʽ��ʾ����*/
UINT ThreadFunc1(LPVOID lpParam)
{
	thread_packet_info* info = (thread_packet_info *)lpParam;
	CMFCCDlg *dlg = (CMFCCDlg *)(info->dlg);
	packet_Info pac_info = info->info;
	CString result;
	CString result_hex;
	int j = 0;//����ָ��
	for(size_t i=0;i< pac_info.len;i++){
		if(pac_info.info[i]>=32 && pac_info.info[i] <=126)//�ǿ����ַ�
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
			//���� ����Ϣ �� ������㡱
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