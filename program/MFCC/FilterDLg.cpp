// FilterDLg.cpp : 实现文件
//

#include "stdafx.h"
#include "MFCC.h"
#include "FilterDLg.h"
#include "Resource.h"
#include <fstream>
#include <istream>
#include <string>
using namespace std;
// CFilterDLg 对话框

IMPLEMENT_DYNAMIC(CFilterDLg, CDialog)

CFilterDLg::CFilterDLg(CWnd* pParent /*=NULL*/)
	: CDialog(CFilterDLg::IDD, pParent)
{
		final_result = "";
}

CFilterDLg::~CFilterDLg()
{
}

//void CFilterDLg::DoDataExchange(CDataExchange* pDX)
//{
//		CDialog::DoDataExchange(pDX);
//
//	
//}


BEGIN_MESSAGE_MAP(CFilterDLg, CDialog)
//		ON_BN_CLICKED(IDC_BUTTON1, &CFilterDLg::OnBnClickedButton1)
ON_BN_CLICKED(IDC_BUTTON1, &CFilterDLg::OnOK)
//ON_BN_CLICKED(IDC_BUTTON1, &CFilterDLg::OnBnClickedButton1)
//ON_LBN_DBLCLK(IDC_LIST1, &CFilterDLg::OnLbnDblclkList1)
ON_LBN_SELCHANGE(IDC_LIST1, &CFilterDLg::OnLbnSelchangeList1)
ON_BN_CLICKED(IDC_CHANGEADD, &CFilterDLg::OnBnClickedChangeadd)
ON_BN_CLICKED(IDC_APPEND, &CFilterDLg::OnBnClickedAppend)
ON_WM_CLOSE()
ON_BN_CLICKED(IDC_SELECT, &CFilterDLg::OnBnClickedSelect)
END_MESSAGE_MAP()


// CFilterDLg 消息处理程序


BOOL CFilterDLg::OnInitDialog()
{
		CDialog::OnInitDialog();
		CFont m_font;
		m_font.CreateFont(18,0,0,0,100,FALSE,FALSE,0, 1,OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY, DEFAULT_PITCH|FF_SWISS,_T("宋体")); 

		CListBox* m_Filter = (CListBox*)this->GetDlgItem(IDC_LIST1);
		m_Filter->SetFont(&m_font);

		map<string,string> the_init;
		the_init.insert(pair<string,string>("tcp","tcp only"));
		the_init.insert(pair<string,string>("arp","arp only"));
		the_init.insert(pair<string,string>("udp","udp only"));
		string filename = "D:\\data.dat";
		fstream fin;
		fin.open(filename.c_str(),ios::in);
		m_Filter->AddString(CString(""));
		if(fin.is_open())
		{
				string s1,s2;
				while(getline(fin,s1)){
						getline(fin,s2);
						filters.insert(pair<string,string>(s2,s1));
						m_Filter->AddString(CString(s2.c_str()));
				}
				fin.close();
		}
		else{
				fstream fout;
				fout.open(filename.c_str(),ios::out);
				map<string,string>::iterator iter = the_init.begin();
				for(;iter!=the_init.end();iter++){
						fout<<iter->first<<endl;
						fout<<iter->second<<endl;
						m_Filter->AddString(CString((iter->second).c_str()));
						filters.insert(*iter);
				}
				fout.close();
		}

		return TRUE;
}
char * CFilterDLg::cs2ca(CString str)
{
    char *ptr;
    #ifdef _UNICODE
    LONG len;
    len = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);
    ptr = new char [len+1];
    memset(ptr,0,len + 1);
    WideCharToMultiByte(CP_ACP, 0, str, -1, ptr, len + 1, NULL, NULL);
    #else
    ptr = new char [str.GetAllocLength()+1];
    sprintf(ptr,_T("%s"),str);
    #endif
    return ptr;
}
void CFilterDLg::OnLbnSelchangeList1()
{
		// TODO: 在此添加控件通知处理程序代码
		CListBox* m_Filter = (CListBox*)this->GetDlgItem(IDC_LIST1);
		int cur = m_Filter->GetCurSel();
		if(cur!=0)
		{
			CString str;
			m_Filter->GetText(cur,str);
			CEdit *edit1 = (CEdit *)this->GetDlgItem(IDC_FILTER_NAME);
			CEdit *edit2 = (CEdit *)this->GetDlgItem(IDC_FILTER_STRING);
			edit1->SetWindowText((LPCTSTR)str);
			string s = string(cs2ca(str));
			string s1 = filters[s];
			edit2->SetWindowText(CString(s1.c_str()));
		}
		
}

void CFilterDLg::OnBnClickedChangeadd()
{
		// TODO: 在此添加控件通知处理程序代码
		CEdit *edit1 = (CEdit *)this->GetDlgItem(IDC_FILTER_NAME);
		CEdit *edit2 = (CEdit *)this->GetDlgItem(IDC_FILTER_STRING);
		CString s1;edit1->GetWindowText(s1);
		CString s2;edit2->GetWindowText(s2);
		if(s1.Trim()=="")
		{
				MessageBox(_T("输入非法"));
				return;
		}
		string ss1 = string(cs2ca(s1));
		string ss2 = string(cs2ca(s2));
		CListBox* m_Filter = (CListBox*)this->GetDlgItem(IDC_LIST1);
		int cur = m_Filter->GetCurSel();
		if(cur>0)
		{
			CString str;
			m_Filter->GetText(cur,str);
			map<string,string>::iterator iter = filters.find(string(cs2ca(str)));
			filters.erase(iter);
			filters[ss1] = ss2;
			m_Filter->DeleteString(cur);
			m_Filter->AddString(CString(ss1.c_str()));

			
		}

		/*
		//filters[ss1] = ss2;
		if(filters.find(ss1) !=filters.end())
		{
				if(filters[ss1] != ss2){
						filters[ss1] = ss2;
				}
		}
		else{
				CListBox* m_Filter = (CListBox*)this->GetDlgItem(IDC_LIST1);
				filters[ss1] = ss2;
				m_Filter->AddString(CString(ss1.c_str()));
		}*/
}

void CFilterDLg::OnBnClickedAppend()
{
		CEdit *edit1 = (CEdit *)this->GetDlgItem(IDC_FILTER_NAME);
		CEdit *edit2 = (CEdit *)this->GetDlgItem(IDC_FILTER_STRING);
		CString s1;edit1->GetWindowText(s1);
		CString s2;edit2->GetWindowText(s2);
		if(s1.Trim()=="")
		{
				MessageBox(_T("输入非法"));
				return;
		}
		string ss1 = string(cs2ca(s1));
		string ss2 = string(cs2ca(s2));
		//filters[ss1] = ss2;
		if(filters.find(ss1) ==filters.end())
		{
				CListBox* m_Filter = (CListBox*)this->GetDlgItem(IDC_LIST1);
				filters[ss1] = ss2;
				m_Filter->AddString(CString(ss1.c_str()));
		}
}

void CFilterDLg::OnClose()
{
		string filename = "D://data.dat";
		fstream fout;
		fout.open(filename.c_str(),ios::out);
		for(map<string,string>::iterator iter = filters.begin();iter!=filters.end();++iter)
		{
				fout<<iter->second<<endl;
				fout<<iter->first<<endl;
				
		}
		fout.close();
		
		CDialog::OnClose();
}

void CFilterDLg::OnBnClickedSelect()
{
		CListBox* m_Filter = (CListBox*)this->GetDlgItem(IDC_LIST1);
		int cur = m_Filter->GetCurSel();
		if(cur>0)
		{
			CString str;
			m_Filter->GetText(cur,str);
			CString result = CString(filters[string(cs2ca(str))].c_str());
			final_result = result;
			CDialog::OnOK();
		}
}
