#pragma once

#include <map>
#include <vector>
// CShowDlg �Ի���

class CShowDlg : public CDialog
{
	DECLARE_DYNAMIC(CShowDlg)

public:
	CShowDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CShowDlg();

// �Ի�������
	enum { IDD = IDD_STATISTIC };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
		afx_msg void OnPaint();
		virtual BOOL OnInitDialog();
		void set_Data(std::vector<CString> &,std::vector<long>&);
public:
		std::vector<CString> protocol_strs;
		std::vector<long> protocol_num;
};
