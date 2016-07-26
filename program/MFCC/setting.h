//用来设置一些参数
#pragma once
#include "stdafx.h"
#include "pcap.h"

const int BUFFER_SIZE = 65536;//存储包信息的缓冲区的大小 以字节为单位
const int SLEEP_TIME = 100;//线程睡眠的时间，控制显示速率
const CString TMPFILENAME = _T("tmp.pdmp");

//ipv4 地址
typedef struct ipv4_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ipv4_address;
	//IPv4 首部
typedef struct ipv4_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service) 
    u_short tlen;           // 总长(Total length) 
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ipv4_address  saddr;      // 源地址(Source address)
    ipv4_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ipv4_header;

/*ipv6地址*/
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
	u_short aaa[8];//无用的，不需要处理
	ipv6_address saddr;//源地址
	ipv6_address daddr;//目的地址
}ipv6_header;
/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;
typedef struct ether_header{
	u_char dmac[6];//6字节 目的Mac地址
	u_char smac[6];//6字节 源Mac地址
	u_short type;//类型
}ether_header;

typedef struct tcp_header{
	u_short sport;//源端口
	u_short dport;//目的端口
	u_long no;//序号
	u_long ack;//确认号
	u_short flags;//后六位分别是 URG ACK PSH RST SYN FIN
	u_short window;//窗口
	u_short test;//检验和
	u_short urge;//紧急指针
	u_long other;//选项和填充
}tcp_header;
typedef struct arp_header{
		u_short htype;//硬件类型
		u_short ptype;//协议类型
		u_char hlen;//硬件地址长度
		u_char plen;//协议地址长度
		u_short oper;//操作
		u_char smac[6];//发送端MAC地址
		ipv4_address sip;//发送端IP地址
		u_char dmac[6];//目的端MAC地址
		ipv4_address dip;//目的端IP地址
}arp_header;
typedef struct icmp_header{
		u_char type;//类型
		u_char code;//代码
		u_short test;//校检和
		//注 由于ICMP报文种类太多，未做详细分析

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
		STOP,//起始状态
		SCAN,//扫描状态
		SUSPEND,//暂停扫描
		FILTER//扫描后过滤
};
enum KIND{
		KIND_FILE,//扫描类型为文件
		KIND_PORT,//扫描类型为网卡
		KIND_NULL
};
enum SAVE{
		SAVE_FILE,
		SAVE_NULL
};
typedef struct packet_Info{
	u_char info[BUFFER_SIZE];//记录包的信息，65536可以保证都存储下来
	long no;//记录包的编号
	bpf_u_int32 len;//记录包的长度
	Protocol_Enum pro;//记录协议编号，便于存储
	bool operator ==(const packet_Info &in) const
	{
		return in.no == no;
	}
}packet_Info;
