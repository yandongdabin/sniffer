// MFCCDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MFCC.h"
#include "MFCCDlg.h"
#include <vector>
#include "pcap.h"
#include <algorithm>
#include <iterator>
#include "thread_one.h"
#include "thread_two.h"
#include "FilterDLg.h"
#include "String_Chinese.h"
#include "String_English.h"
#include "string_res.h"
#include "ShowDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

UINT ThreadFunc(LPVOID lpParam);

std::vector<packet_Info> packet_Infos;//用来记录包信息的全局变量
long long TOTAL_PACKET_NUM;
long TCP_NUM,UDP_NUM,ICMP_NUM,OSPF_NUM,IGMP_NUM,ARP_NUM;
CRITICAL_SECTION g_cs;

volatile bool switch_thread;
volatile bool switch_main_thread;

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CMFCCDlg 对话框





const CString CMFCCDlg::list_strs[]={_T("序号"),_T("到达时间"),_T("源IP地址"),_T("端口号"),_T("目的IP地址"),_T("端口号"),_T("协议名"),_T("包长度")};
const int CMFCCDlg::list_strs_width[] = {7,15,20,10,20,10,8,10};

/*用来传递给线程的参数 声明为全局变量 如若不然会出现线程的访问冲突*/
thread_info m_Info;
thread_packet_info m_Info1;
thread_info t_info;

CMFCCDlg::CMFCCDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CMFCCDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_SNIFFER);
	MENU_INDEX = -1;
	edit_color = 1;//设置过滤框的颜色
	Filterdlg = NULL;//过滤对话框
	m_tmpFile = NULL;//默认的存储文件句柄
	PRO_STATUS = STOP;//程序状态
	PRO_KIND = KIND_NULL;//当前期待的文件类型
	dev_handle = NULL;//打开的连接
	string_Res = new String_Chinese();//语言包
}
CMFCCDlg::~CMFCCDlg(){
		if(string_Res!=NULL)
				delete(string_Res);
}
void CMFCCDlg::DoDataExchange(CDataExchange* pDX)
{
		CDialog::DoDataExchange(pDX);
		DDX_Control(pDX, IDC_LIST1, m_InfoList);
		DDX_Control(pDX, IDC_TREE1, m_InfoTree);
		DDX_Control(pDX, IDC_EDIT2, m_InfoText);
		DDX_Control(pDX, IDC_EDIT3, m_InfoText_);
		DDX_Control(pDX, IDC_EDIT1, m_Edit);
		DDX_Control(pDX, IDC_BUTTON1, m_FilterBtn);
		DDX_Control(pDX, IDC_BUTTON2, m_ResetBtn);
}
BEGIN_MESSAGE_MAP(CMFCCDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
ON_WM_CTLCOLOR()
ON_WM_SIZE()
ON_WM_ERASEBKGND()
ON_COMMAND(ID_START, &CMFCCDlg::OnStart)
ON_WM_CLOSE()

ON_NOTIFY(NM_CLICK, IDC_LIST1, &CMFCCDlg::OnNMClickList1)
ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST1, &CMFCCDlg::OnLvnColumnclickList1)
ON_NOTIFY ( NM_CUSTOMDRAW, IDC_LIST1, &CMFCCDlg::OnCustomdrawMyList)
ON_COMMAND(ID_STOP, &CMFCCDlg::OnStop)
ON_BN_CLICKED(IDC_BUTTON1, &CMFCCDlg::OnBnClickedButton1)
ON_EN_CHANGE(IDC_EDIT1, &CMFCCDlg::OnEnChangeEdit1)
ON_COMMAND(ID_SET_FILTER, &CMFCCDlg::OnSetFilter)
ON_BN_CLICKED(IDOK, &CMFCCDlg::OnOK)
ON_BN_CLICKED(IDC_BUTTON2, &CMFCCDlg::OnRest)
ON_COMMAND(ID_SUSPEND, &CMFCCDlg::OnSuspend)
ON_EN_SETFOCUS(IDC_EDIT2, &CMFCCDlg::OnEnSetfocusEdit2)
ON_WM_TIMER()
ON_EN_KILLFOCUS(IDC_EDIT2, &CMFCCDlg::OnEnKillfocusEdit2)
ON_COMMAND(ID_FILTER_CUR, &CMFCCDlg::OnFilterCur)
ON_COMMAND(ID_COUNT, &CMFCCDlg::OnCount)
ON_COMMAND(ID_ENG, &CMFCCDlg::OnEng)
ON_COMMAND(ID_CHI, &CMFCCDlg::OnChi)
ON_COMMAND(ID_ABOUT, &CMFCCDlg::OnAbout)
END_MESSAGE_MAP()


// CMFCCDlg 消息处理程序

BOOL CMFCCDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	
	
	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}
	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
		CRect rect;      
    GetClientRect(&rect);    
    old.x=rect.right-rect.left;  
    old.y=rect.bottom-rect.top;  
    int cx = GetSystemMetrics(SM_CXFULLSCREEN);  
    int cy = GetSystemMetrics(SM_CYFULLSCREEN);  
    CRect rt;  
    SystemParametersInfo(SPI_GETWORKAREA,0,&rt,0);  
    cy = rt.bottom;  
    MoveWindow(0, 0, cx, cy);

		 m_Imagelist.Create(16,16,ILC_COLOR16 |ILC_MASK,5,8);  //创建图像列表        
		 m_Imagelist.Add(AfxGetApp()->LoadIcon(IDI_ICON1));    
		 m_Imagelist.Add(AfxGetApp()->LoadIcon(IDI_ICON2));   
		 m_Imagelist.Add(AfxGetApp()->LoadIcon(IDI_ICON3));  
		 m_Imagelist.Add(AfxGetApp()->LoadIcon(IDI_ICON7));  
		 m_Imagelist.Add(AfxGetApp()->LoadIcon(IDI_ICON4));    
		 m_Imagelist.Add(AfxGetApp()->LoadIcon(IDI_ICON5));   
 

	m_Toolbar.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP
      | CBRS_GRIPPER | CBRS_TOOLTIPS | CBRS_FLYBY | CBRS_SIZE_DYNAMIC);
       m_Toolbar.LoadToolBar(IDR_TOOLBAR1);  //IDR_TOOLBAR1既是步骤一中增加的toolbar resource
       
       RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
			 m_Toolbar.GetToolBarCtrl().SetImageList(&m_Imagelist);
			 m_StatusBar.Create(WS_CHILD|WS_VISIBLE|SBT_OWNERDRAW, CRect(0,0,0,0), this, 0);

    int strPartDim[2]= {100,200}; //分割数量
    m_StatusBar.SetParts(2, strPartDim);

                  //设置状态栏文本
	m_StatusBar.SetText(_T("包总数:"), 0, 0);
	m_StatusBar.SetText(_T("0"), 1, 0);
	m_StatusBar.SetBkColor(RGB(180,20,180));
	//初始化 listctrl
	CRect list_rect;
	m_InfoList.GetClientRect(list_rect);
	int list_width = list_rect.right - list_rect.left;
	LVCOLUMN lvColumn;
    int nCol;
	
	for(int i=0;i<8;i++)
	{
		lvColumn.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH;
		lvColumn.fmt = LVCFMT_LEFT;
		lvColumn.cx = list_width * list_strs_width[i]/100;
		lvColumn.pszText = (LPWSTR)(LPCTSTR)list_strs[i];
		nCol = m_InfoList.InsertColumn(i, &lvColumn);
	}
	DWORD dwStyle = m_InfoList.GetExtendedStyle();
	dwStyle |= LVS_EX_GRIDLINES | LVS_EX_ONECLICKACTIVATE |LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER;
	m_InfoList.SetExtendedStyle(dwStyle);
	m_InfoList.SetBkColor(RGB(240,240,150));

	m_InfoTree.SetBkColor(RGB(255,200,240));


	//设置过滤输入框
	CFont m_Font;
		m_Font.CreateFont(0,0,0,0,170,true,false,false,
		CHINESEBIG5_CHARSET,OUT_CHARACTER_PRECIS,
		CLIP_CHARACTER_PRECIS,DEFAULT_QUALITY,
		FF_SWISS,_T("Courier New"));
	m_Edit.SetFont(&m_Font);
	m_Font.Detach();
	m_Font.CreateFont(0,0,0,0,130,false,false,false,
			CHINESEBIG5_CHARSET,OUT_CHARACTER_PRECIS,
		CLIP_CHARACTER_PRECIS,DEFAULT_QUALITY,
		FF_SWISS,_T("黑体"));
	m_InfoText.SetFont(&m_Font);
	m_InfoText_.SetFont(&m_Font);
	m_Font.Detach();
	//初始化菜单栏
	std::vector<CString> v = get_All_Devs();
	GetMenu()->GetSubMenu(1)->AppendMenuW(MF_STRING,ID_NEWMENU+0,_T("脱机文件"));
	GetMenu()->GetSubMenu(1)->EnableMenuItem(1,MF_BYPOSITION|MF_DISABLED|MF_GRAYED); 
	for(size_t i =1;i<=v.size();i++)
	GetMenu()->GetSubMenu(1)->
	AppendMenu(MF_STRING,ID_NEWMENU + i,(LPCTSTR)v[i-1]);
	GetMenu()->CheckMenuItem(ID_CHI,MF_CHECKED);//设置默认语言是汉语
	//初始化控件，防止用户误操作
	this->m_FilterBtn.EnableWindow(FALSE);
	this->m_ResetBtn.EnableWindow(FALSE);
	this->m_Edit.EnableWindow(FALSE);
	InitializeCriticalSection(&g_cs);//初始化临界区
	//初始化线程指针
	m_pThread = NULL;
	
	
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCCDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}
void CMFCCDlg::OnPaint()
{
	
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
	
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
HBRUSH CMFCCDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  在此更改 DC 的任何属性

	// TODO:  如果默认的不是所需画笔，则返回另一个画笔
	switch( nCtlColor )
	{
	case CTLCOLOR_EDIT:
			if(edit_color == 1)
			{
				pDC->SetBkColor(RGB(174,254,178));
		 }
			else if(edit_color == 2)
			{
				
					pDC->SetBkColor(RGB(255,226,198));  
			}

	}
	return hbr;
}

void CMFCCDlg::OnSize(UINT nType, int cx, int cy)
{
		BOOL is_minimize = this->IsIconic();
		if(is_minimize) return;
		CDialog::OnSize(nType, cx, cy);
		float fsp[2];  
    POINT Newp; //获取现在对话框的大小  
    CRect recta;      
    GetClientRect(&recta);     //取客户区大小    
    Newp.x=recta.right-recta.left;  
    Newp.y=recta.bottom-recta.top;  
    fsp[0]=(float)Newp.x/old.x;  
    fsp[1]=(float)Newp.y/old.y;  
    CRect Rect;  
    int woc;  
    CPoint OldTLPoint,TLPoint; //左上角  
    CPoint OldBRPoint,BRPoint; //右下角  
    HWND  hwndChild=::GetWindow(m_hWnd,GW_CHILD);  //列出所有控件    
    while(hwndChild)      
    {      
        woc=::GetDlgCtrlID(hwndChild);//取得ID  
        GetDlgItem(woc)->GetWindowRect(Rect);    
        ScreenToClient(Rect);    
        OldTLPoint = Rect.TopLeft();    
        TLPoint.x = long(OldTLPoint.x*fsp[0]);    
        TLPoint.y = long(OldTLPoint.y*fsp[1]);    
        OldBRPoint = Rect.BottomRight();    
        BRPoint.x = long(OldBRPoint.x *fsp[0]);    
        BRPoint.y = long(OldBRPoint.y *fsp[1]);    
        Rect.SetRect(TLPoint,BRPoint);    
        GetDlgItem(woc)->MoveWindow(Rect,TRUE);  
        hwndChild=::GetWindow(hwndChild, GW_HWNDNEXT);      
    }  
    old=Newp;
}

BOOL CMFCCDlg::OnEraseBkgnd(CDC* pDC)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	//return false;
	return CDialog::OnEraseBkgnd(pDC);
}
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


std::vector<CString> CMFCCDlg::get_All_Devs()
{
	std::vector<CString> v;
	pcap_if_t *alldevs;
  pcap_if_t *d;
  char errbuf[PCAP_ERRBUF_SIZE];
    
    /* 获取本地机器设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
				::MessageBox(NULL,string_Res->FAIL_TO_GET_ADAPTER,NULL,MB_OK);
		exit(1);
    }
	int i=0;
	for(d=alldevs;d;d=d->next)
	{
		strcpy(dev_name[i],d->name);
		if(d->addresses!=NULL)
		{
			netmask[i++] = ntohl(((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr)>>8;
		}
		else
			netmask[i++] = 0xffffff;
		CString str;
		//以下是把char*转为宽字符
		USES_CONVERSION;
		str.Format(_T("%s"),A2W(d->description));
		v.push_back(str);
	}
	pcap_freealldevs(alldevs);
	return v;
}
int CMFCCDlg::open_Dev(char *name)
{
	checkThreadStatus();
	if(PRO_STATUS != STOP)
	{
			MessageBox(string_Res->ALREADY_SCAN);
		return -1;
	}
	dev_handle= pcap_open(name,          // 设备名
                        65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
						PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                        1000,             // 读取超时时间
                        NULL,             // 远程机器验证
                        errbuf            // 错误缓冲池
                        );
	//pcap_setmode(dev_handle, MODE_STAT);
	if(dev_handle == NULL) return 0;
	m_Info.dlg = this;
	m_Info.handle = dev_handle;
	m_Info.if_store = true;
	m_pThread = AfxBeginThread(ThreadFunc,&m_Info);
	return 1;
}
void CMFCCDlg::OnStart()
{
	
	if(m_pThread!=NULL && PRO_STATUS==SUSPEND)
	{
			m_pThread->ResumeThread();
			PRO_STATUS = SCAN;
			return;
	}
	if(PRO_STATUS != STOP)
	{
			MessageBox(string_Res->STIIL_SCAN_ERROR);
			return;
	}
	checkThreadStatus();
	switch_thread = true;
	if(PRO_KIND == KIND_NULL)
	{
		MessageBox(string_Res->NULL_OPEN);
		return;
	}
	char source[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	if(PRO_KIND == KIND_FILE)
	{
		pcap_createsrcstr(source,         // 源字符串
                            PCAP_SRC_FILE,  // 我们要打开的文件
                            NULL,           // 远程主机
                            NULL,           // 远程主机端口
														cs2ca(this->FilePathOpen),        // 我们要打开的文件名
                            errbuf          // 错误缓冲区
                     );
		open_Dev(source);
	}
	else
	{
		open_Dev(this->dev_name[MENU_INDEX]);
	}
	this->m_FilterBtn.EnableWindow(TRUE);
	this->m_ResetBtn.EnableWindow(TRUE);
	this->m_Edit.EnableWindow(TRUE);
		m_tmpFile = pcap_dump_open(this->dev_handle,cs2ca(TMPFILENAME));
	if(m_tmpFile == NULL)
						{
								MessageBox(string_Res->OPEN_ERROR,NULL,MB_ICONERROR | MB_OK);
						}
	PRO_STATUS = SCAN;
	
}

void CMFCCDlg::OnStop()
{
	if(PRO_STATUS == SUSPEND)
			m_pThread->ResumeThread();
	EnterCriticalSection(&g_cs);
	switch_thread = false;
	LeaveCriticalSection(&g_cs);
	if(m_pThread !=NULL)
	{
		DWORD dwRet = WaitForSingleObject(m_pThread, 5000);
		if(dwRet == WAIT_OBJECT_0)
		{
				//do nothing
		}
		else
		{
				 DWORD dwRet = 0;
				 GetExitCodeThread(m_pThread, &dwRet);
				 TerminateThread(m_pThread, dwRet);
		}
		m_pThread = NULL;
	}
	/*如果需要保存文件，则把暂存文件复制并重命名为用户所需的文件*/
	if(this->m_tmpFile != NULL)
			pcap_dump_close(m_tmpFile);
	//m_tmpFile = NULL;
	if(FilePathSave != _T("")){
			int res = CopyFile(TMPFILENAME,FilePathSave,FALSE);
			if(res == 0)
			{
					MessageBox(string_Res->SAVE_ERROR);
			}
	}
	/*重置菜单项*/
	for(int i=2;i<=10;i++)
	{
		GetMenu()->GetSubMenu(1)->EnableMenuItem(i,MF_BYPOSITION|MF_ENABLED);
		GetMenu()->CheckMenuItem(ID_NEWMENU + i,MF_UNCHECKED);
	}
	GetMenu()->CheckMenuItem(ID_NEWMENU + 1,MF_UNCHECKED);
	this->m_FilterBtn.EnableWindow(FALSE);
	this->m_ResetBtn.EnableWindow(FALSE);
	this->m_Edit.EnableWindow(FALSE);

	PRO_STATUS = STOP;
	PRO_KIND = KIND_NULL;
	dev_handle = NULL;
}
void CMFCCDlg::OnClose()
{

	switch_thread = false;//关闭线程
	CDialog::OnClose();
	if(Filterdlg!=NULL) delete(Filterdlg);
	DeleteFile(TMPFILENAME);

}

void CMFCCDlg::OnNMClickList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMHEADER phdr = reinterpret_cast<LPNMHEADER>(pNMHDR);
	POSITION ps = m_InfoList.GetFirstSelectedItemPosition();
	if(ps == NULL) return;
	int nItem = m_InfoList.GetNextSelectedItem(ps) + 1;//获得选中的行号
	packet_Info info;
	info.no = nItem;
	long no = packet_Infos[nItem].no;
	m_InfoText_.SetWindowTextW(_T(""));

	//开启线程处理之
	m_Info1.dlg = this;
	m_Info1.info =  packet_Infos[nItem];
	AfxBeginThread(ThreadFunc1,&m_Info1);
	*pResult = 0;
}

/*当点击List Ctrl 标题时的事件*/
void CMFCCDlg::OnLvnColumnclickList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	*pResult = 0;
}
/*设置CListCtrl item的背景颜色*/
void CMFCCDlg::OnCustomdrawMyList(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>( pNMHDR );
    *pResult = CDRF_DODEFAULT;
	if ( CDDS_PREPAINT == pLVCD->nmcd.dwDrawStage )
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
    else if ( CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage )
	{
		*pResult = CDRF_NOTIFYITEMDRAW;

	}
	else if ( (CDDS_ITEMPREPAINT | CDDS_SUBITEM) == pLVCD->nmcd.dwDrawStage)
	{
		COLORREF clrNewTextColor, clrNewBkColor;    
		int  nItem = static_cast<int>( pLVCD->nmcd.dwItemSpec);
		if(nItem % 2 ==1)
		{
			clrNewTextColor = RGB(0,0,0);
			clrNewBkColor = RGB(186,85,211);
		}
		else
		{
			clrNewTextColor = RGB(0,0,0);
			clrNewBkColor = RGB(135,206,235);	
		}
		/*CString str = m_InfoList.GetItemText(nItem,6);
		if(str == "UDP")
		{
			clrNewTextColor = RGB(186,85,211);	 //Set the text to red
			clrNewBkColor = RGB(255,255,255);	 //Set the bkgrnd color to blue
		}
		else if(str == "TCP")
		{
			clrNewTextColor = RGB(135,206,235);	 //Set the text to red
			clrNewBkColor = RGB(255,255,255);;	 //Set the bkgrnd color to blue
		}
		else if(str == "ICMP")
		{
			clrNewTextColor =  RGB(0,255,127);	 //Set the text to red
			clrNewBkColor = RGB(255,255,255);	 //Set the bkgrnd color to blue
		}
		/*if(nItem%2 ==0)
		{
			clrNewTextColor = RGB(0,0,0);	 //Set the text to red
			clrNewBkColor = RGB(240,240,240);	 //Set the bkgrnd color to blue
		}
		else
		{
			clrNewTextColor = RGB(0,0,0);	 //Leave the text black
			clrNewBkColor = RGB(255,255,255);	//leave the bkgrnd color white
		}
		else
		{
			clrNewTextColor = RGB(240,240,240);	 //Set the text to red
			clrNewBkColor = RGB(255,255,255);	 //Set the bkgrnd color to blue
		}*/
		pLVCD->clrText = clrNewTextColor;
		pLVCD->clrTextBk = clrNewBkColor;
		*pResult = CDRF_DODEFAULT;
	}
}

/**处理网络适配器的响应事件*/
BOOL CMFCCDlg::OnCommand(WPARAM wParam, LPARAM lParam) 
{
    UINT uMsg=LOWORD(wParam);
    char buf[2];
    for(UINT i=1;i<=10;i++)
    {
        if(uMsg==ID_NEWMENU+i)
        {
						
						UINT state = GetMenu()->GetMenuState(ID_NEWMENU+i, MF_BYCOMMAND);
						if(state & MF_CHECKED)//当前已经被选择，则取消选中
						{
								this->GetMenu()->CheckMenuItem(ID_NEWMENU+i,MF_UNCHECKED);
								MENU_INDEX = -1;
								PRO_KIND = KIND_NULL;
								break;
						}//当前已经被选择，则选中后禁止菜单
						else
						{
								for(UINT j=0;j<=10;j++)
								{
										this->GetMenu()->CheckMenuItem(ID_NEWMENU+j,MF_UNCHECKED);
										GetMenu()->GetSubMenu(1)->EnableMenuItem(j,MF_BYPOSITION|MF_DISABLED|MF_GRAYED); 
								}
								this->GetMenu()->CheckMenuItem(ID_NEWMENU+i,MF_CHECKED);
								MENU_INDEX = i-1;
								PRO_KIND = KIND_PORT;
								break;
						}
        }
    }
		if(uMsg == ID_START_TOOl)
		{
				//模拟菜单消息的点击
				PostMessage(WM_COMMAND, MAKEWPARAM(ID_START, BN_CLICKED), NULL);
		}
		if(uMsg == ID_STOP_TOOL)
		{
				//模拟菜单消息的点击
				PostMessage(WM_COMMAND, MAKEWPARAM(ID_STOP, BN_CLICKED), NULL);
		}
		if(uMsg == ID_SUSPEND_TOOL)
		{
					//模拟菜单消息的点击
				PostMessage(WM_COMMAND, MAKEWPARAM(ID_SUSPEND, BN_CLICKED), NULL);
		}
		if(uMsg == ID_OPEN_TOOL)
		{
				checkThreadStatus();
				if(PRO_STATUS != STOP)
				{
						MessageBox(string_Res->ALREADY_SCAN,NULL,MB_ICONERROR | MB_OK);
						return FALSE;
				}
				CString FilePathName;  
				CFileDialog dlg(TRUE,
						_T(".dmp"),
						NULL,
						NULL,
						_T("Dump Files (*.pdmp)|*.pdmp|All Files (*.*)|*.*||"),
						NULL					
						); 
				if(dlg.DoModal()==IDOK)  
						FilePathName=dlg.GetPathName();
				FilePathOpen = FilePathName;
				if(FilePathOpen.Trim()!=_T(""))
						{
						
								for(int i=2;i<=10;i++)
								{
										GetMenu()->CheckMenuItem(ID_NEWMENU+i,MF_UNCHECKED);
										GetMenu()->GetSubMenu(1)->EnableMenuItem(i,MF_BYPOSITION|MF_DISABLED); 	
								}
								this->GetMenu()->GetSubMenu(1)->ModifyMenuW(1,MF_BYPOSITION | MF_STRING | MF_DISABLED,ID_NEWMENU+0,FilePathOpen);

								this->GetMenu()->CheckMenuItem(ID_NEWMENU+0,MF_CHECKED);
								PRO_KIND = KIND_FILE;
						}
				
		}
		if(uMsg == ID_SAVE_TOOL)
		{
					CString FilePathName;  
					CFileDialog dlg(FALSE,
						_T(".dmp"),
						NULL,
						NULL,
						_T("Dump Files (*.pdmp)|*.pdmp|All Files (*.*)|*.*||"),
						NULL					
						); 
				if(dlg.DoModal()==IDOK)  
						FilePathSave=dlg.GetPathName();	
		}
		if(uMsg == ID_SETTING_TOOL)
		{
				MessageBox(_T("ID_SETTING_TOOL"));
		}
    return CDialog::OnCommand(wParam, lParam);
}

char * CMFCCDlg::cs2ca(CString str)
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
bool CMFCCDlg::checkThreadStatus(){
		DWORD status;
		if(m_pThread!=NULL)
		{
				::GetExitCodeThread(m_pThread,&status);
				if(status != STILL_ACTIVE)
				{
						//有可能消息传递的慢，会耽误后面的处理，所以提前改变一下状态
						PRO_STATUS = STOP;
						PRO_KIND = KIND_NULL;
						m_pThread = NULL;
						PostMessage(WM_COMMAND, MAKEWPARAM(ID_STOP, BN_CLICKED), NULL);
				}
		}
		if(t_pThread!=NULL)
		{
				GetExitCodeThread(t_pThread,&status);
				if(status != STILL_ACTIVE)
				{
					PRO_STATUS = STOP;
					tmp_handle = NULL;
					t_pThread = NULL;
				}
		}
		return true;

}

//开始过滤
void CMFCCDlg::OnBnClickedButton1()
{
	CString str;
	m_Edit.GetWindowTextW(str);

	if(m_pThread != NULL)
	{
		m_pThread->SuspendThread();//先终止扫描
		struct bpf_program fcode;
		char* str_buf = cs2ca(str);
		if(pcap_compile(this->dev_handle, &fcode,str_buf, 1, netmask[this->MENU_INDEX])<0)
		{
				MessageBox(string_Res->GRAMMER_ERROR);
				m_pThread->ResumeThread();
				return;
		}
		pcap_setfilter(dev_handle, &fcode);
		pcap_freecode(&fcode);
		m_pThread->ResumeThread();
	}
}

void CMFCCDlg::OnEnChangeEdit1()
{
		if(dev_handle!=NULL)
		{
				CString str;
				m_Edit.GetWindowTextW(str);
				char *buf = cs2ca(str);
				struct bpf_program fcode;
				if(pcap_compile(this->dev_handle, &fcode,buf, 1, netmask[this->MENU_INDEX])<0)
				{
						edit_color = 2;
				}
				else
						edit_color = 1;
				pcap_freecode(&fcode);
		}
}

void CMFCCDlg::OnSetFilter()
{
		// TODO: 在此添加命令处理程序代码
		//Filterdlg	= new CFilterDLg();
		Filterdlg = new CFilterDLg();
		Filterdlg->DoModal();
		CString str = Filterdlg->final_result;
		if(PRO_STATUS == SCAN || PRO_STATUS == SUSPEND)
		{
				this->m_Edit.SetWindowText(str);
				PostMessage(WM_COMMAND, MAKEWPARAM(IDC_BUTTON1, BN_CLICKED), NULL);
		}
		else if(PRO_STATUS == FILTER)
		{
				struct bpf_program fcode;
				char* str_buf = cs2ca(str);
				if(pcap_compile(this->tmp_handle, &fcode,str_buf, 1, netmask[this->MENU_INDEX])<0)
				{
						MessageBox(string_Res->GRAMMER_ERROR);
						if(t_pThread!=NULL)
						t_pThread->ResumeThread();
						return;
				}
				pcap_setfilter(tmp_handle, &fcode);
				pcap_freecode(&fcode);
				if(t_pThread != NULL)
				{
						t_pThread->ResumeThread();
				}
		}
}
void CMFCCDlg::OnOK()
{
		return;
}

void CMFCCDlg::OnRest()
{
		// TODO: 在此添加控件通知处理程序代码
		m_Edit.SetWindowTextW(_T(""));
		CString str("");
		char *str_buf = cs2ca(str);
		struct bpf_program fcode;
		
		pcap_compile(this->dev_handle, &fcode,str_buf, 1, netmask[this->MENU_INDEX]);
		pcap_setfilter(dev_handle, &fcode);
		pcap_freecode(&fcode);
}
/*暂停*/
void CMFCCDlg::OnSuspend()
{
		// TODO: 在此添加命令处理程序代码
		if(m_pThread != NULL)
		{
				m_pThread->SuspendThread();
				PRO_STATUS = SUSPEND;
		}
}

void CMFCCDlg::OnEnSetfocusEdit2()
{
		// TODO: 在此添加控件通知处理程序代码
		//SetTimer(EditTimer,100,NULL);
}
void CMFCCDlg::OnEnKillfocusEdit2()
{
		// TODO: 在此添加控件通知处理程序代码
		//KillTimer(EditTimer);
}
void CMFCCDlg::OnTimer(UINT_PTR nIDEvent)
{
		// TODO: 在此添加消息处理程序代码和/或调用默认值
		switch(nIDEvent)
		{
		case EditTimer:
				DWORD pos = this->m_InfoText.GetSel();
				this->m_InfoText_.SetSel(pos);
		}
		CDialog::OnTimer(nIDEvent);
}
/*过滤当前的内容*/
void CMFCCDlg::OnFilterCur()
{
		// TODO: 在此添加命令处理程序代码
		checkThreadStatus();
		if(PRO_STATUS != STOP)
		{
				MessageBox(string_Res->STIIL_SCAN_ERROR);
				return;
		}
		CString filename = _T("tmp.tmp");
		int res = CopyFile(TMPFILENAME,_T("tmp.tmp"),FALSE);
		if(res == 0){
				MessageBox(string_Res->FAIL_TO_FILTER);
				return;
		}
		PRO_STATUS = FILTER;
		char source[PCAP_BUF_SIZE];
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_createsrcstr(source,         // 源字符串
                            PCAP_SRC_FILE,  // 我们要打开的文件
                            NULL,           // 远程主机
                            NULL,           // 远程主机端口
														cs2ca(filename),        // 我们要打开的文件名
                            errbuf          // 错误缓冲区
                            );
		tmp_handle= pcap_open(source,          // 设备名
                        65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
						PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                        1000,             // 读取超时时间
                        NULL,             // 远程机器验证
                        errbuf            // 错误缓冲池
                        );
		if(tmp_handle == NULL)
		{
				MessageBox(string_Res->FAIL_TO_FILTER);
				return;
		}

	

	switch_thread = true;
	t_info.dlg = this;
	t_info.handle = tmp_handle;
	t_info.if_store = false;

	t_pThread = AfxBeginThread(ThreadFunc,&t_info,0,0,CREATE_SUSPENDED);
	PostMessage(WM_COMMAND, MAKEWPARAM(ID_SET_FILTER, BN_CLICKED), NULL);
	WaitForSingleObject(t_pThread, INFINITE);//等待程序结束

	//PRO_STATUS = STOP;
}

void CMFCCDlg::OnCount()
{
		// TODO: 在此添加命令处理程序代码
		//this->checkThreadStatus();
		if(this->PRO_STATUS != STOP)
		{
				MessageBox(string_Res->NOT_DATA);
				return;
		}
		showDlg = new CShowDlg();
		long nums[] = {TCP_NUM,UDP_NUM,ICMP_NUM,OSPF_NUM,IGMP_NUM,ARP_NUM};
		int count = sizeof(nums)/sizeof(long);
		vector<long> vn(nums,nums +count);
		CString strs [] = {_T("TCP"),_T("UDP"),_T("ICMP"),_T("OSPF"),_T("IGMP"),_T("ARP")};
		vector<CString> vs(strs,strs+count);
		showDlg->set_Data(vs,vn);
		showDlg->DoModal();
}

void CMFCCDlg::OnEng()
{
		if(string_Res!=NULL)
				delete(string_Res);
		string_Res = new String_English();
		GetMenu()->CheckMenuItem(ID_CHI,MF_UNCHECKED);
		GetMenu()->CheckMenuItem(ID_ENG,MF_CHECKED);
		//GetMenu()->CheckMenuItem(
}

void CMFCCDlg::OnChi()
{
			if(string_Res!=NULL)
				delete(string_Res);
		string_Res = new String_Chinese();
		GetMenu()->CheckMenuItem(ID_ENG,MF_UNCHECKED);
		GetMenu()->CheckMenuItem(ID_CHI,MF_CHECKED);
}

void CMFCCDlg::OnAbout()
{
		CAboutDlg dlg;
		dlg.DoModal();
}
