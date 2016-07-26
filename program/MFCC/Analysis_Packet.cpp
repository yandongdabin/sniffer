#include "stdafx.h"
#include "Analysis_Packet.h"
#include <vector>
#include <map>
#include "setting.h"
using namespace std;

std::map<int,std::map<CString,CString>> Analysis_Packet::analysis(u_char * pac){
		
		std::map<int,std::map<CString,CString>> result;
		map<CString,CString> m_str;
		m_str = analysis_physics(pac);
		result.insert(pair<int,map<CString,CString>>(0,m_str));
		m_str = analysis_datalink(pac);
		result.insert(pair<int,map<CString,CString>>(1,m_str));
		m_str = analysis_internet(pac);
		result.insert(pair<int,map<CString,CString>>(2,m_str));
		m_str = analysis_tranmission(pac);
		result.insert(pair<int,map<CString,CString>>(3,m_str));
		//m_str = analysis_application(pac);
		//result.insert(pair<int,map<CString,CString>>(4,m_str));
		return result;

}
map<CString,CString> Analysis_Packet::analysis_physics(u_char *data)
{
		map<CString,CString> m;
		return m;
}
map<CString,CString> Analysis_Packet::analysis_datalink(u_char * data){

		map<CString,CString> result;
		ether_header* eh;
		eh = (ether_header *)data;
		CString dmac;
		dmac.Format(_T("%02x:%02x:%02x:%02x:%02x:%02x"),eh->dmac[0],eh->dmac[1],eh->dmac[2],eh->dmac[3],eh->dmac[4],eh->dmac[5]);
		CString smac;
		smac.Format(_T("%02x:%02x:%02x:%02x:%02x:%02x"),eh->smac[0],eh->smac[1],eh->smac[2],eh->smac[3],eh->smac[4],eh->smac[5]);
		u_short type = ntohs(eh->type);
		CString type_str;
		if(type == 0x0800)
				type_str = _T("IPV4");
		else if(type== 0x0806)
				type_str = _T("ARP");
		else if(type == 0x86DD)
				type_str = _T("IPV6");
		else type_str = _T("unknown");

		
		result.insert(pair<CString,CString>(_T("源Mac地址"),smac));
		result.insert(pair<CString,CString>(_T("目的Mac地址"),dmac));
		result.insert(pair<CString,CString>(_T("协议"),type_str));
		if(type == 0x0806)//ARP
		{
				arp_header *ah= (arp_header *)(data+14);
				CString content;
				content.Format(_T("%x.%x.%x.%x.%x.%x > %x.%x.%x.%x.%x.%x ethertype ARP(0x0806),length :%d" ),ah->smac[0],ah->smac[1],ah->smac[2],ah->smac[3],ah->smac[4],ah->smac[5],ah->dmac[0],ah->dmac[1],ah->dmac[2],ah->dmac[3],ah->dmac[4],ah->dmac[5],ah->plen);
				CString ipcontent;
				int oper = ntohs(ah->oper);
				if(oper == 1)
						ipcontent.Format(_T("request who-has %d,%d,%d,%d tell %d,%d,%d,%d"),ah->dip.byte1,ah->dip.byte2,ah->dip.byte3,ah->dip.byte4,
						ah->sip.byte1,ah->sip.byte2,ah->sip.byte3,ah->sip.byte4
						);
				else if(oper == 2)
						ipcontent.Format(_T("reply %d,%d,%d,%d is-at %x,%x,%x,%x,%x,%x"),ah->sip.byte1,ah->sip.byte2,ah->sip.byte3,ah->sip.byte4,ah->smac[0],ah->smac[1],ah->smac[2],ah->smac[3],ah->smac[4],ah->smac[5]);
					
				//result.insert(pair<CString,CString>(_T("协议类型"),_T("ARP")));
				result.insert(pair<CString,CString>(_T("概要信息"),content));
				result.insert(pair<CString,CString>(_T("详细信息"),ipcontent));
		}
		return result;
}
map<CString,CString> Analysis_Packet::analysis_internet(u_char *data){
		map<CString,CString> result;
		ether_header* eh;
		eh = (ether_header *)data;
		u_short type = ntohs(eh->type);
		if(type == 0x0800)//IPV4
		{
				ipv4_header *ih= (ipv4_header *)(data +14);
				CString sourceIP;
				sourceIP.Format(_T("%d.%d.%d.%d"),ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4);
				CString dstIP;
				dstIP.Format(_T("%d.%d.%d.%d"),ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
				int header_len = ((ih->ver_ihl) & (0xF))<<2;
				int total_len = ntohs(ih->tlen);
				CString hl_str;
				hl_str.Format(_T("%d  %d"),header_len,total_len);

				result.insert(pair<CString,CString>(_T("协议类型"),_T("IPV4")));
				result.insert(pair<CString,CString>(_T("源IP地址"),sourceIP));
				result.insert(pair<CString,CString>(_T("目的IP地址"),dstIP));
				result.insert(pair<CString,CString>(_T("头部长度  总长度"),hl_str));
		}
		else if(type== 0x86DD)//IPV6
		{
				
		}
		
		
		return result;
}
map<CString,CString> Analysis_Packet::analysis_tranmission(u_char *data){
		map<CString,CString> m;
		return m;
}
map<CString,CString> Analysis_Packet::analysis_application(u_char *data){
		map<CString,CString> m;
		return m;
}