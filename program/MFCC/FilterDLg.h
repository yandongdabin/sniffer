#pragma once
#include "afxwin.h"
#include "Resource.h"
#include <map>
#include <string>
// CFilterDLg 对话框

class CFilterDLg : public CDialog
{
	DECLARE_DYNAMIC(CFilterDLg)

public:
	CFilterDLg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CFilterDLg();

// 对话框数据
	enum { IDD = IDD_FILTER_DIALOG };

protected:
//	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
		//CListBox m_Filter;
		virtual BOOL OnInitDialog();
//		afx_msg void OnBnClickedButton1();
//		afx_msg void OnOK();
//		afx_msg void OnBnClickedButton1();
//		afx_msg void OnLbnDblclkList1();

		CString final_result;
		std::map<std::string,std::string> filters;
		afx_msg void OnLbnSelchangeList1();
public:
		char *cs2ca(CString str);
		afx_msg void OnBnClickedChangeadd();
		afx_msg void OnBnClickedAppend();
		afx_msg void OnClose();
		afx_msg void OnBnClickedSelect();
};
