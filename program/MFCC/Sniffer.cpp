#include "stdafx.h"
#include "Sniffer.h"
#include "pcap.h"
#include "MFCCDlg.h"
#include <iostream>
#include <cstring>


/* ���������͵�IP��ַת�����ַ������͵� */
#define IPTOSBUFFERS    12

using namespace std;

//ipv4 ��ַ
typedef struct ipv4_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
	}ipv4_address;
	//IPv4 �ײ�
typedef struct ipv4_header{
    u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char  tos;            // ��������(Type of service) 
    u_short tlen;           // �ܳ�(Total length) 
    u_short identification; // ��ʶ(Identification)
    u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char  ttl;            // ���ʱ��(Time to live)
    u_char  proto;          // Э��(Protocol)
    u_short crc;            // �ײ�У���(Header checksum)
    ipv4_address  saddr;      // Դ��ַ(Source address)
    ipv4_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
    u_int   op_pad;         // ѡ�������(Option + Padding)
}ipv4_header;

/*ipv6��ַ*/
typedef struct ipv6_address
{
	u_short word1;
	u_short word2;
	u_short word3;
	u_short word4;
	u_short word5;
	u_short word6;
	u_short word7;
	u_short word8;
}ipv6_address;
typedef struct ipv6_header{
	u_short aaa[8];//���õģ�����Ҫ����
	ipv6_address saddr;//Դ��ַ
	ipv6_address daddr;//Ŀ�ĵ�ַ
}ipv6_header;
/* UDP �ײ�*/
typedef struct udp_header{
    u_short sport;          // Դ�˿�(Source port)
    u_short dport;          // Ŀ�Ķ˿�(Destination port)
    u_short len;            // UDP���ݰ�����(Datagram length)
    u_short crc;            // У���(Checksum)
}udp_header;
typedef struct ether_header{
	u_short dmac[3];//6�ֽ� Ŀ��Mac��ַ
	u_short smac[3];//6�ֽ� ԴMac��ַ
	u_short type;//����
}ether_header;


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
std::vector<CString> Sniffer::get_All_Devs()
{
	std::vector<CString> v;
	pcap_if_t *alldevs;
    pcap_if_t *d;

	//pcap_addr_t *a;
  
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* ��ȡ���ػ����豸�б� */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        //fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
	int i=0;
	for(d=alldevs;d;d=d->next)
	{
		
		strcpy(dev_name[i],d->name);
		if(d->addresses!=NULL)
		{
			//netmask[i++] = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
			//cout<</*((struct sockaddr_in *)(d->addresses->addr))->sin_addr.S_un.S_addr<<endl*/d->addresses->addr->sa_family<<endl;
		}
		else
			netmask[i++] = 0xffffff;
		//dev_name[i++] = d->name;
		CString str;
		str.Format(_T("%s"),d->description);
		::MessageBox(NULL,(LPCWSTR)d->description,NULL,MB_OK);
		v.push_back(str);
	}
	pcap_freealldevs(alldevs);
	return v;
}
int Sniffer::open_Dev(char *name,CMFCCDlg *dlg)
{
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	struct tm *ltime;
	int res;
	time_t local_tv_sec;
	dev_handle= pcap_open(name,          // �豸��
                        65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
						PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                        1000,             // ��ȡ��ʱʱ��
                        NULL,             // Զ�̻�����֤
                        errbuf            // ���󻺳��
                        );
	if(dev_handle == NULL) return 0;
	
	/*while((res = pcap_next_ex( dev_handle, &header, &pkt_data)) >= 0){
        
        if(res == 0)
         
            continue;
        
       
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(dev_handle));
        return -1;
    }*/
	pcap_loop(dev_handle, 0, packet_handler, (u_char*)dlg);
	return 1;

}
/* ÿ�β������ݰ�ʱ��libpcap�����Զ���������ص����� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ipv4_header *ih;
	ether_header *eh;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

	CMFCCDlg *dlg = (CMFCCDlg *)param;
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
    
    //printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
   
    eh = (ether_header *)(pkt_data);
	char ip_type[10];
	u_short ip_type_value = ntohs(eh->type);
	if(ip_type_value == 0x0800)
		strcpy(ip_type,"ipv4");
	else if(ip_type_value == 0x86DD)
		strcpy(ip_type,"ipv6");
	//printf("%s\n",ip_type);
	ih = (ipv4_header *) (pkt_data +
        14); //��̫��ͷ������

    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

	/*��ʼ��ȡ��Ϣ*/
    CString sourceIP;
	sourceIP.Format(_T("%c.%c.%c.%c.%c"),ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4);
	CString dstIP;
	dstIP.Format(_T("%c.%c.%c.%c.%c"),ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
	CString sourcePort;
	sourcePort.Format(_T("%d"),sport);
	CString dstPort;
	dstPort.Format(_T("%d"),dport);
	CString pkLen;
	pkLen.Format(_T("%d"),header->len);
	CString comeTime(timestr);
	CString idenPk;
	idenPk.Format(_T("%d"),ih->identification);
	CString proStr = _T("Unknown");
	int tmp = (int)ih->proto;
	if(tmp == 1)
	{
		proStr = _T("ICMP");
	}
	else if(tmp == 2)
	{
		proStr = _T("IGMP");
	}
	else if(tmp == 6)
	{
		proStr = _T("TCP");
	}
	else if(tmp == 17)
	{
		proStr = _T("UDP");
	}
	else if(tmp == 41)
	{
		proStr = _T("IPV6");
	}
	else if(tmp==89)
	{
		proStr = _T("OSPF");
	}
	LVITEM lvItem;
    int nItem;

    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = 0;
    lvItem.iSubItem = 0;
    lvItem.pszText = (LPWSTR)(LPCTSTR)idenPk;
    nItem = dlg->m_InfoList.InsertItem(&lvItem);
	dlg->m_InfoList.SetItemText(nItem, 1, (LPWSTR)(LPCTSTR)sourceIP);
	dlg->m_InfoList.SetItemText(nItem, 2, (LPWSTR)(LPCTSTR)sourcePort);
	dlg->m_InfoList.SetItemText(nItem, 3, (LPWSTR)(LPCTSTR)dstIP);
	dlg->m_InfoList.SetItemText(nItem, 4, (LPWSTR)(LPCTSTR)dstPort);
	dlg->m_InfoList.SetItemText(nItem, 5, (LPWSTR)(LPCTSTR)proStr);
	dlg->m_InfoList.SetItemText(nItem, 6, (LPWSTR)(LPCTSTR)idenPk);
	dlg->m_InfoList.SetItemText(nItem, 7, (LPWSTR)(LPCTSTR)pkLen);

	/*dlg->m_InfoList.InsertColumn(0,&idenPk);
	dlg->m_InfoList.InsertColumn(1,&sourceIP);
	dlg->m_InfoList.InsertColumn(2,&sourcePort);
	dlg->m_InfoList.InsertColumn(3,&dstIP);
	dlg->m_InfoList.InsertColumn(4,&dstPort);
	dlg->m_InfoList.InsertColumn(5,&proStr);
	dlg->m_InfoList.InsertColumn(6,&idenPk);
	dlg->m_InfoList.InsertColumn(7,&pkLen);*/
}