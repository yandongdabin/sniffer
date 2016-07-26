#pragma once

#include <map>
#include <vector>
// CShowDlg 对话框

class CShowDlg : public CDialog
{
	DECLARE_DYNAMIC(CShowDlg)

public:
	CShowDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CShowDlg();

// 对话框数据
	enum { IDD = IDD_STATISTIC };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
		afx_msg void OnPaint();
		virtual BOOL OnInitDialog();
		void set_Data(std::vector<CString> &,std::vector<long>&);
public:
		std::vector<CString> protocol_strs;
		std::vector<long> protocol_num;
};
