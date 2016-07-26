// ShowDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MFCC.h"
#include "ShowDlg.h"
#include <cmath>
#include <vector>
#include <numeric>
using namespace std;

// CShowDlg 对话框

IMPLEMENT_DYNAMIC(CShowDlg, CDialog)

CShowDlg::CShowDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CShowDlg::IDD, pParent)
{

}

CShowDlg::~CShowDlg()
{
}

void CShowDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CShowDlg, CDialog)
		ON_WM_PAINT()
END_MESSAGE_MAP()

void CShowDlg::set_Data(std::vector<CString> & str,std::vector<long>&num){
		this->protocol_strs = str;
		this->protocol_num = num;
}
// CShowDlg 消息处理程序

void CShowDlg::OnPaint()
{
		CPaintDC dc(this); 
		int width = 120;//柱状图的宽
		int gap = 150;//柱状图的间隔
		long sum = std::accumulate(protocol_num.begin(),protocol_num.end(),0);
		long max = 0;
		for(int i=0;i<protocol_num.size();i++)
				if(protocol_num[i]>max)
						max = protocol_num[i];
		CRect rect;  //客户区大小
		CWnd *pWnd;//窗口句柄
		CDC *pDC;//窗口上下文


		/*绘制柱状图*/
		pWnd = GetDlgItem(IDC_BITMAP_ONE);
		pDC = pWnd->GetDC();
		pWnd->GetClientRect(&rect);  
		int logic_width = 1000 * rect.Width() / rect.Height();
		int logic_height = 1000;
		pDC->SetMapMode(MM_ISOTROPIC);
		pDC->SetWindowExt(logic_width,logic_height);
		pDC->SetViewportExt(rect.Width(),-rect.Height());
		pDC->SetViewportOrg(0,rect.Height()); 
		
		RECT rect_;
		POINT txtps;//文字的位置
		LOGFONT logfont;
		CFont font;
		ZeroMemory(&logfont,sizeof(logfont));
		font.CreateFontIndirect(&logfont);
		//lstrcpy((LPWSTR)logfont.lfFaceName,(LPSTR)"楷体_GB2312"); 
		logfont.lfWeight=500; 
		logfont.lfWidth=15; 
		logfont.lfHeight=30; 
		logfont.lfEscapement=0; 
		logfont.lfUnderline=FALSE; 
		logfont.lfItalic=FALSE; 
		logfont.lfStrikeOut=FALSE; 
		logfont.lfCharSet=GB2312_CHARSET; 

		pDC->SelectObject(&logfont);
		map<CString,CString> tmp_map_str;
		for(int i=0;i<protocol_num.size();i++)
		{
				CString str_t;
				str_t.Format(_T("%d"),protocol_num[i]);
				tmp_map_str.insert(pair<CString,CString>(protocol_strs[i],str_t));
				double rate = protocol_num[i]* 1.0 / max;
				int height = static_cast<int>((logic_height-width)*rate);
				CBrush brush(RGB(255-i*140,i*200,255-i*100)),*oldbrush; 
				CPen pen(PS_SOLID,1,RGB(i*140,i*200,i*100)),*oldPen;
				oldbrush=pDC->SelectObject(&brush); 
				oldPen = pDC->SelectObject(&pen);
				pDC->SetTextColor(RGB(255-i*30,i*30, 255-i*80));
				rect_.left = i*(width+gap);
				rect_.top = height;
				rect_.right = rect_.left + width;
				rect_.bottom = 0;
				txtps.y = rect_.top + width / 2;
				txtps.x = rect_.left;

				//输出柱状
				pDC->Rectangle(&rect_);
				//输出协议名称
				//CString tmp_str = protocol_strs[i];
				//tmp_str.AppendFormat(_T("(%ld)"),protocol_num[i]);
				pDC->TextOut(txtps.x,txtps.y,protocol_strs[i]);
				pDC->SelectObject(&oldbrush); 
				pDC->SelectObject(&oldPen); 

		}
		ReleaseDC(pDC);



		/*绘制饼状图*/
		pWnd = GetDlgItem(IDC_BITMAP_TWO);
		pWnd->GetClientRect(&rect); 
		pDC = pWnd->GetDC();
		pDC->SetMapMode(MM_ISOTROPIC);
		pDC->SetWindowExt(logic_width,logic_height);
		pDC->SetViewportExt(rect.Width(),-rect.Height());
		pDC->SetViewportOrg(rect.Width()/2,rect.Height()/2);
		int rect_width = 480;
		int center_x = 0;
		int center_y = 0;
		CRect basic_Rect(center_x - rect_width,center_y+rect_width,center_x + rect_width,center_y - rect_width);
		POINT start = {rect_width,0};//起始点
		POINT end;
		map<CString,COLORREF> tmp_map;
	
		double total_angle = 0;
		double one_circle_angle = 360.0;
		double PI = 3.1415926;
		for(int i=0;i<protocol_num.size();i++)
		{
				
				if(protocol_num[i] == 0) continue;
				
				COLORREF cf = RGB(255-i*140,i*200,255-i*100);
				tmp_map.insert(pair<CString,COLORREF>(protocol_strs[i],cf));
				CBrush brush_circle(cf),*oldbrush_circle; 
				CPen pen_circle(PS_SOLID,1,RGB(i*140,i*200,i*100)),*oldPen_circle;
				oldbrush_circle=pDC->SelectObject(&brush_circle); 
				oldPen_circle = pDC->SelectObject(&pen_circle);
				double rate = protocol_num[i] * 1.0 / sum;
				total_angle += rate * one_circle_angle;
				int px = static_cast<int>(rect_width*cos(total_angle*PI/180));
				int py = static_cast<int>(rect_width*sin(total_angle*PI/180));
				
				end.x = px;
				end.y = py;
				
			
				pDC->Pie(&basic_Rect,start,end);
				start = end;
				pDC->SelectObject(&oldbrush_circle); 
				pDC->SelectObject(&oldPen_circle); 

		}
		ReleaseDC(pDC);
		pWnd = GetDlgItem(IDC_BITMAP_FLAG);
		pWnd->GetClientRect(&rect); 
		pDC = pWnd->GetDC();
		pDC->SetMapMode(MM_ISOTROPIC);
		pDC->SetWindowExt(500,500);
		pDC->SetViewportExt(rect.Width(),rect.Height());
		pDC->SetViewportOrg(10,10);
		
		CRect start_rect;
		int tmp_width = 150;
		int tmp_height = 130;
		start_rect.left = 20;
		start_rect.right = start_rect.left + tmp_width;
		start_rect.top = 20;
		start_rect.bottom = start_rect.top + tmp_height;


		for(map<CString,COLORREF>::iterator iter = tmp_map.begin();iter!=tmp_map.end();++iter)
		{
				txtps.x = start_rect.right + 20;
				txtps.y = (start_rect.top + start_rect.bottom) / 2 - 20;
				CBrush brush(iter->second);
				pDC->FillRect(&start_rect,&brush);
				pDC->TextOut(txtps.x,txtps.y,iter->first);

				start_rect.top+=150;
				start_rect.bottom+=150;
		
		}
		
		ReleaseDC(pDC);
		pWnd = GetDlgItem(IDC_BITMAP_DOWN);
		pWnd->GetClientRect(&rect); 
		pDC = pWnd->GetDC();
		pDC->SetMapMode(MM_ISOTROPIC);
		pDC->SetWindowExt(500,300);
		pDC->SetViewportExt(rect.Width(),rect.Height());
		pDC->SetTextColor(RGB(100,100,100));
		txtps.x = 20;
		txtps.y = 20;
		//pDC->SetViewportOrg(0,rect.Height());
		for(map<CString,CString>::iterator iter = tmp_map_str.begin();iter!=tmp_map_str.end();++iter)
		{
				CString s;
				s = iter->first + CString(":") +iter->second;
				pDC->TextOut(txtps.x,txtps.y,s);
				txtps.x += 200;
		}

		pWnd->InvalidateRect(&rect);
		
}

BOOL CShowDlg::OnInitDialog()
{
		CDialog::OnInitDialog();
		

		return TRUE;  
}
