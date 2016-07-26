#pragma once
#include "stdafx.h"
#include "pcap.h"
#include "MFCCDlg.h"
#include "setting.h"
#include <vector>
using namespace std;
extern std::vector<packet_Info> packet_Infos;
extern long long TOTAL_PACKET_NUM;
extern long TCP_NUM;
extern long UDP_NUM;
extern long ICMP_NUM;
extern long OSPF_NUM;
extern long IGMP_NUM;
extern long ARP_NUM;
extern volatile bool switch_thread;
extern volatile bool switch_main_thread;
extern CRITICAL_SECTION g_cs;
/*此线程的目的是抓包 并存储在内存中*/
UINT ThreadFunc(LPVOID lpParam)
{
	
	TOTAL_PACKET_NUM = 0;
	TCP_NUM=0;
	UDP_NUM=0;
	ICMP_NUM=0;
	OSPF_NUM=0;
	IGMP_NUM = 0;
	ARP_NUM = 0;
	packet_Infos.clear();
	packet_Info info;
	info.info[0] = '\0';
	info.no = 0;
	packet_Infos.push_back(info);

	thread_info *infos = (thread_info*)lpParam;

	pcap_t *dev_handle = (infos->handle);

	CMFCCDlg* dlg =(CMFCCDlg *)infos->dlg; 
	
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	struct tm *ltime;
	int res;
	int header_length;//用来记录TCP或者UDP的首部长度
	time_t local_tv_sec;
	u_long ser_no = 0;//存储包的编号

	if(dlg->m_InfoList.GetItemCount()>0)
	dlg->m_InfoList.DeleteAllItems();//删除所有内容
	 /* 获取数据包 */
  while((res=pcap_next_ex(dev_handle, &header, &pkt_data)) >= 0){
    EnterCriticalSection(&g_cs);
				if(!switch_thread)
				{
						//MessageBox(NULL,_T("false"),NULL,MB_OK);
						LeaveCriticalSection(&g_cs);
						break;
				}
		LeaveCriticalSection(&g_cs);
		
		if(res == 0)
            //超时时间到 
            continue;
    struct tm *ltime;
    char timestr[16];
    ipv4_header *ih;
		ether_header *eh;
    udp_header *uh;
		tcp_header *tp;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    eh = (ether_header *)(pkt_data);
		CString ip_type;
		u_short ip_type_value = ntohs(eh->type);
		if(ip_type_value == 0x0800)
		ip_type = _T("ipv4");
		else if(ip_type_value == 0x86DD)
		ip_type = _T("ipv6");
		
		
		ih = (ipv4_header *) (pkt_data +
        14); //以太网头部长度

	CString proStr = _T("Unknown");
	Protocol_Enum pro;
	int tmp = (int)ih->proto;

	if(tmp == 1)
	{
		proStr = _T("ICMP");
		pro = ICMP;
		ICMP_NUM++;
	}
	else if(tmp == 2)
	{
		proStr = _T("IGMP");
		pro = IGMP;
		IGMP_NUM++;
	}
	else if(tmp == 6)
	{
		proStr = _T("TCP");
		pro = TCP;
		TCP_NUM++;
	}
	else if(tmp == 17)
	{
		proStr = _T("UDP");
		pro = UDP;
		UDP_NUM++;
	}
	else if(tmp == 41)
	{
		proStr = _T("IPV6");
		pro = IPV6;
	}
	else if(tmp==89)
	{
		proStr = _T("OSPF");
		pro = OSPF;
		OSPF_NUM++;
	}
	else if(ip_type_value == 0x0806)
	{
		proStr = _T("ARP");
		pro = ARP;
		ARP_NUM++;
	}
	else
				continue;

  ip_len = (ih->ver_ihl & 0xf) * 4;
  uh = (udp_header *) ((u_char*)ih + ip_len);
	tp = (tcp_header *) ((u_char*)ih + ip_len);
  if(tmp == 17)
	{
		sport = ntohs( uh->sport );
		dport = ntohs( uh->dport );
	}
	else if(tmp == 6)
	{
		sport = ntohs(tp->sport);
		dport = ntohs(tp->dport);
		//header_length = ((ntohs(tp->flags))>>(16-4))&(0x0F);//计算TCP数据包的头部长度
	}

	/*开始读取信息*/
  CString sourceIP;
	sourceIP.Format(_T("%d.%d.%d.%d"),ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4);
	CString dstIP;
	dstIP.Format(_T("%d.%d.%d.%d"),ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
	CString sourcePort;
	sourcePort.Format(_T("%d"),sport);
	CString dstPort;
	dstPort.Format(_T("%d"),dport);
	CString pkLen;
	pkLen.Format(_T("%d"),header->len);
	CString comeTime(timestr);

	CString ser_no_str;
	ser_no_str.Format(_T("%07d"),++ser_no);
	CString times_;
	USES_CONVERSION;
	times_.Format(_T("%s"),A2W(timestr));
	
	LVITEM lvItem;
  int nItem;

  lvItem.mask = LVIF_TEXT;
	lvItem.iItem = dlg->m_InfoList.GetItemCount();
  lvItem.iSubItem = 0;
  lvItem.pszText = (LPWSTR)(LPCTSTR)ser_no_str;
  nItem = (dlg->m_InfoList).InsertItem(&lvItem);
	dlg->m_InfoList.SetItemText(nItem, 0, (LPWSTR)(LPCTSTR)ser_no_str);
	dlg->m_InfoList.SetItemText(nItem, 1, (LPWSTR)(LPCTSTR)times_);
	dlg->m_InfoList.SetItemText(nItem, 2, (LPWSTR)(LPCTSTR)sourceIP);
	dlg->m_InfoList.SetItemText(nItem, 3, (LPWSTR)(LPCTSTR)sourcePort);
	dlg->m_InfoList.SetItemText(nItem, 4, (LPWSTR)(LPCTSTR)dstIP);
	dlg->m_InfoList.SetItemText(nItem, 5, (LPWSTR)(LPCTSTR)dstPort);
	dlg->m_InfoList.SetItemText(nItem, 6, (LPWSTR)(LPCTSTR)proStr);
	dlg->m_InfoList.SetItemText(nItem, 7, (LPWSTR)(LPCTSTR)pkLen);
	dlg->m_InfoList.EnsureVisible(dlg->m_InfoList.GetItemCount()-1,TRUE);

	
	
	TOTAL_PACKET_NUM++;//统计数目包的数目增加
	CString str_num;
	str_num.Format(_T("%lld"),TOTAL_PACKET_NUM);
	
	dlg->m_StatusBar.SetText((LPCTSTR)str_num, 1, 0);
	packet_Info pac_info;

	//存储数据包的内容
	try{
		if(pkt_data != NULL && header!=NULL)
		{
				memcpy(pac_info.info,pkt_data/*+14+ip_len*/,header->len);
				pac_info.no = packet_Infos[packet_Infos.size()-1].no+1;
				pac_info.len = header->len;
				pac_info.pro = pro;
				packet_Infos.push_back(pac_info);
		}
	}
	catch(...)
	{
			::MessageBox(NULL,_T("发生异常2"),NULL,MB_OK);
	}
	if(!infos->if_store) continue;
	/*以下是存储内容并计数  如果只是过滤数据包 则跳过*/
	//Sleep(SLEEP_TIME);
	pcap_dump((u_char*)dlg->m_tmpFile, header, pkt_data);
	}
		
	
	return 0;
}