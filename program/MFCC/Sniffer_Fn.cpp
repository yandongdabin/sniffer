#include "Sniffer_Fn.h"
#include "stdafx.h"
#include "pcap.h"
#include "MFCCDlg.h"
#include <iostream>
#include <cstring>

char errbuf[PCAP_ERRBUF_SIZE];
char dev_name[10][100];//记录设备的名字，用于打开设备
bpf_u_int32 netmask[10];//记录各个设备的子网掩码，用于过滤数据包
std::vector<CString> get_All_Devs()
{
	std::vector<CString> v;
	pcap_if_t *alldevs;
    pcap_if_t *d;

	//pcap_addr_t *a;
  
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* 获取本地机器设备列表 */
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