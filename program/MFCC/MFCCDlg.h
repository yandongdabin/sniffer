// MFCCDlg.h : 头文件
//

#pragma once

#include "afxcmn.h"
#include "afxwin.h"
#include "pcap.h"
#include <vector>
#include <string>
#include "Resource.h"
#include "setting.h"
#include "FilterDLg.h"
#include "string_res.h"
#include "String_Chinese.h"
#include "String_English.h"
#include "ShowDlg.h"
// CMFCCDlg 对话框
class CMFCCDlg : public CDialog
{
// 构造
public:
	CMFCCDlg(CWnd* pParent = NULL);	// 标准构造函数
	virtual ~CMFCCDlg();
// 对话框数据
	enum { IDD = IDD_MFCC_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持
	BOOL CMFCCDlg::OnCommand(WPARAM wParam, LPARAM lParam);

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
	

	POINT old;

	//List Ctrl的参数
	
public:
	CToolBar m_Toolbar;//工具栏
	CStatusBarCtrl m_StatusBar;//状态栏
	CListCtrl m_InfoList;
	CMenu m_menu;
	int MENU_INDEX;
	CFilterDLg *Filterdlg;
	CShowDlg *showDlg;
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	CTreeCtrl m_InfoTree;
	CEdit m_InfoText;
	CEdit m_InfoText_;
	afx_msg void OnSize(UINT nType, int cx, int cy);

	const static int LIST_SIZE = 8;
	const static CString list_strs[];
	static const int list_strs_width[];
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	CEdit m_Edit;
	CWinThread *m_pThread;//扫描线程的句柄
	CWinThread *t_pThread;//截取后扫描的线程句柄
	pcap_dumper_t *m_tmpFile;
	CString FilePathSave;
	CString FilePathOpen;
	String_Res *string_Res;

	/*定义程序状态*/
	STATUS PRO_STATUS;//program status
	KIND PRO_KIND;//program kind

	int edit_color;
	
	typedef struct packet_Info
	{
		u_char info[65536];
		long no;
	}packet_Info;

public:
	typedef unsigned long u_long;
	std::vector<CString> get_All_Devs();
	int open_Dev(char *name);
	friend void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

	char *cs2ca(CString str);

	/*此函数的作用是检查线程当前的状态，应对的情况是当文件已经扫描完毕但是程序的状态还没有变，虽然没有bug但会引起用户不适*/
	bool checkThreadStatus();
protected:
	

private:
	pcap_t *dev_handle;//保存打开的链接
	pcap_t *tmp_handle;//保存截取后打开的链接

public:
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev_name[10][100];//记录设备的名字，用于打开设备
	u_int netmask[10];//记录各个设备的子网掩码，用于过滤数据包
	CImageList m_Imagelist;//工具栏图标

	afx_msg void OnStart();
	afx_msg void OnClose();
	afx_msg void OnNMClickList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnColumnclickList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnCustomdrawMyList(NMHDR *pNMHDR, LRESULT *pResult);

	afx_msg void OnStop();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnSetFilter();
	afx_msg void OnOK();
	afx_msg void OnRest();
	CButton m_FilterBtn;
	CButton m_ResetBtn;
	afx_msg void OnSuspend();
	CRichEditCtrl m_InfoRichText;
	afx_msg void OnEnSetfocusEdit2();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnEnKillfocusEdit2();
	afx_msg void OnFilterCur();
	afx_msg void OnCount();
	afx_msg void OnEng();
	afx_msg void OnChi();
	afx_msg void OnAbout();
};

typedef struct thread_info{
	CMFCCDlg *dlg;
	pcap_t *handle;
	bool if_store;
}thread_info;
typedef struct thread_packet_info{
	CMFCCDlg *dlg;
	packet_Info info;
}thread_packet_info;
;