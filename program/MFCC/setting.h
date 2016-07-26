//��������һЩ����
#pragma once
#include "stdafx.h"
#include "pcap.h"

const int BUFFER_SIZE = 65536;//�洢����Ϣ�Ļ������Ĵ�С ���ֽ�Ϊ��λ
const int SLEEP_TIME = 100;//�߳�˯�ߵ�ʱ�䣬������ʾ����
const CString TMPFILENAME = _T("tmp.pdmp");

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
	u_char dmac[6];//6�ֽ� Ŀ��Mac��ַ
	u_char smac[6];//6�ֽ� ԴMac��ַ
	u_short type;//����
}ether_header;

typedef struct tcp_header{
	u_short sport;//Դ�˿�
	u_short dport;//Ŀ�Ķ˿�
	u_long no;//���
	u_long ack;//ȷ�Ϻ�
	u_short flags;//����λ�ֱ��� URG ACK PSH RST SYN FIN
	u_short window;//����
	u_short test;//�����
	u_short urge;//����ָ��
	u_long other;//ѡ������
}tcp_header;
typedef struct arp_header{
		u_short htype;//Ӳ������
		u_short ptype;//Э������
		u_char hlen;//Ӳ����ַ����
		u_char plen;//Э���ַ����
		u_short oper;//����
		u_char smac[6];//���Ͷ�MAC��ַ
		ipv4_address sip;//���Ͷ�IP��ַ
		u_char dmac[6];//Ŀ�Ķ�MAC��ַ
		ipv4_address dip;//Ŀ�Ķ�IP��ַ
}arp_header;
typedef struct icmp_header{
		u_char type;//����
		u_char code;//����
		u_short test;//У���
		//ע ����ICMP��������̫�࣬δ����ϸ����

}icmp_header;
enum Protocol_Enum
{
	TCP,
	UDP,
	ICMP,
	IGMP,
	IPV6,
	OSPF,
	ARP
};
enum STATUS{
		STOP,//��ʼ״̬
		SCAN,//ɨ��״̬
		SUSPEND,//��ͣɨ��
		FILTER//ɨ������
};
enum KIND{
		KIND_FILE,//ɨ������Ϊ�ļ�
		KIND_PORT,//ɨ������Ϊ����
		KIND_NULL
};
enum SAVE{
		SAVE_FILE,
		SAVE_NULL
};
typedef struct packet_Info{
	u_char info[BUFFER_SIZE];//��¼������Ϣ��65536���Ա�֤���洢����
	long no;//��¼���ı��
	bpf_u_int32 len;//��¼���ĳ���
	Protocol_Enum pro;//��¼Э���ţ����ڴ洢
	bool operator ==(const packet_Info &in) const
	{
		return in.no == no;
	}
}packet_Info;
