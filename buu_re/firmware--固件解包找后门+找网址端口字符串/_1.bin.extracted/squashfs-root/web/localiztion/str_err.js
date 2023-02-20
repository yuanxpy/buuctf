var	ERR_NO_ERROR											=0
var ERR_FS_FILE_OPEN_FAILED									=10

var	ERR_PPPOE_FIXED_IP										=1000
var	ERR_PPPOE_TIMING_SET									=1001
var	ERR_PPPOE_STRING_TOO_LONG								=1002
var	ERR_PPPOE_USERNAME_TOO_LONG								=1003
var	ERR_PPPOE_PWD_TOO_LONG									=1004
var	ERR_PPPOE_AUTO_OFF_WAITE_TIME							=1005
var	ERR_PPPOE_LCP_MRU										=1006
var	ERR_PPPOE_ECHO_REQ_INTERVAL								=1007

var	ERR_DHCP_SERVER_ADDR_POOL_ERROR							=2000
var	ERR_DHCP_SERVER_GATEWAY_ERROR							=2001
var	ERR_DHCP_SERVER_DNS_ERROR								=2002
var	ERR_DHCP_SERVER_BAK_DNS_ERROR							=2003
var	ERR_DHCP_SERVER_LEASE									=2004
var	ERR_DHCP_SERVER_START_IP_ADDR							=2005
var	ERR_DHCP_SERVER_END_IP_ADDR								=2006
var	ERR_DHCP_SERVER_START_BIGGER_END						=2007
var	ERR_DHCP_SERVER_ADD_RANGE								=2008

var	ERR_FIX_MAP_MAC_ADDR_ERROR								=3000
var	ERR_FIX_MAP_IP_ADDR_ERROR								=3001
var	ERR_FIX_MAP_REC_EXIST									=3002
var	ERR_FIX_MAP_PAGE_NUM_ERROR								=3003
var	ERR_FIX_MAP_RECORD_ALREADY_FULL							=3004
var	ERR_FIX_MAP_RECORD_MAC_ALREADY_EXIST					=3005
var	ERR_FIX_MAP_RECORD_IP_ALREADY_EXIST						=3006
var ERR_FIX_MAP_IP_EQUAL_LANIP								=3007

var	ERR_STATIC_ROUTR_ENABLE									=4000
var	ERR_STATIC_ROUTR_DESTINATION_IP							=4001
var	ERR_STATIC_ROUTR_SUBNETMASK_IP							=4002
var	ERR_STATIC_ROUTR_SUBNETMASK_DISMATCH_IP					=4003
var	ERR_STATIC_ROUTR_GATEWAY_IP								=4004
var	ERR_STATIC_ROUTR_NOEMPTY								=4005
var	ERR_STATIC_ROUTR_DUPLICATION							=4006
var	ERR_STATIC_ROUTR_DEFAULT_GATEWAY						=4007
var	ERR_STATIC_ROUTR_NOT_SAME_NETWORK						=4008
var	ERR_STATIC_ROUTR_CONFLICT_LAN_WAN						=4009
var	ERR_STATIC_DEST_CONFLICT_LAN							=4010
var	ERR_STATIC_DEST_CONFLICT_WAN							=4011
var	ERR_STATIC_ROUTR_ALREADY_FULL							=4012
var	ERR_STATIC_ROUTR_SAVE									=4013
var	ERR_STATIC_ROUTR_OTHER									=4014
var	ERR_WAN_DOWN_BANDWIDTH									=4015
var	ERR_WAN_UP_BANDWIDTH									=4016
var ERR_WAN_HOSTNAME										=4017
var ERR_WAN_LINK_MODE_ERROR                				=4018

var	ERR_NETWORK_MTU											=5000
var	ERR_LAN_IP_ERROR										=5001
var	ERR_LAN_MASK_ERROR										=5002
var	ERR_WAN_IP_ERROR										=5003
var	ERR_WAN_MASK_ERROR										=5004
var	ERR_WAN_DNS_ERROR										=5005
var	ERR_WAN_BACKDNS_ERROR									=5006
var	ERR_WAN_GATE_ERROR										=5007
var	ERR_WAN_LAN_CONFLICT									=5008
var	ERR_WAN_TYPE											=5009
var	ERR_LAN_IP_SET											=5010
var	ERR_LAN_MASK_SET										=5011
var	ERR_WAN_IP_SERVER										=5012
var	ERR_WAN_IP_SET											=5013
var	ERR_WAN_MASK_SET										=5014
var	ERR_WAN_DNS_SET											=5015
var	ERR_WAN_GATE_SET										=5016
var	ERR_WAN_MAC_ADDR										=5017
var	ERR_WAN_MAC_DUPLICATE									=5018
var	ERR_WAN_MAC_EQ_LAN_MAC									=5019
var	ERR_SNTP_MONTH											=5020
var	ERR_SNTP_DAY											=5021
var	ERR_SNTP_YEAR											=5022
var	ERR_SNTP_HOUR											=5023
var	ERR_SNTP_MINUTE											=5024
var	ERR_SNTP_SECOND											=5025
var	ERR_SNTP_TIME_SET										=5026
var	ERR_SNTP_TIMEZONE										=5027
var	ERR_SNTP_GET_GMT_FAILED									=5028
var ERR_SAME_WAN_IP											=5029
var ERR_SNTP_SERVER_A                                       =5030
var ERR_SNTP_SERVER_B                                       =5031 
var ERR_SERVER_IP_ERROR	                                    =5032
var	ERR_MAC_WAN_EQUAL_PC					=5033


var	ERR_MORNITOR_PORT_ACTIVE_PORT							=6000
var	ERR_MORNITOR_PORT_PASSIVE_PORT							=6001
var	ERR_MORNITOR_PORT_EQUAL_PORT							=6002
var	ERR_MORNITOR_NONE_PORT									=6003

var	ERR_TFTP_OVER_FILE_LEN									=7000
var	ERR_TFTP_IP_ERROR										=7001

var	ERR_FIREWALL_START_TIME_FORMAT_ERROR					=8000
var	ERR_FIREWALL_END_TIME_FORMAT_ERROR						=8001
var	ERR_FIREWALL_TIME_START_BIGGER_END						=8002
var	ERR_FIREWALL_LAN_IP_FORMAT_ERROR						=8003
var	ERR_FIREWALL_LAN_PORT_FORMAT_ERROR						=8004
var	ERR_FIREWALL_WAN_IP_FORMAT_ERROR						=8005
var	ERR_FIREWALL_WAN_PORT_FORMAT_ERROR						=8006
var	ERR_FIREWALL_PROTOCOL_TYPE_ERROR						=8007
var	ERR_FIREWALL_RECORD_ALREADY_EXIST						=8008
var	ERR_FIREWALL_IP_RECORD_ALREADY_FULL						=8009

var	ERR_FIREWALL_DOMAIN_NAME_LEN_OVER						=9000
var	ERR_FIREWALL_DOMAIN_NAME_ERROR							=9001
var	ERR_FIREWALL_DOMAIN_IS_SUBSET							=9002
var	ERR_FIREWALL_DOMAIN_RECORD_ALREADY_FULL					=9003

var	ERR_FIREWALL_TIME_NOT_FULL								=10000
var	ERR_FIREWALL_TIME_FORMAT_ERROR							=10001
var	ERR_FIREWALL_WZD_TIME_ALREADY_EXIST						=10002
var	ERR_FIREWALL_WZD_TIME_IS_SUBSET							=10003
var	ERR_FIREWALL_WZD_IP_FORMAT_ERROR						=10004
var	ERR_FIREWALL_WZD_ADDR_ALREADY_EXIST						=10005
var	ERR_FIREWALL_WZD_PORT_FORMAT_ERROR						=10006
var	ERR_FIREWALL_WZD_PORT_IS_SUBSET							=10007

var	ERR_MAC_FILTER_PAGE_NUM_ERROR							=11000
var	ERR_MAC_FILTER_RECORD_ALREADY_EXIST						=11001
var	ERR_MAC_FILTER_RECORD_ALREADY_FULL						=11002
var	ERR_MAC_FILTER_FORMAT_ERROR								=11003

var	ERR_REMOTE_MANAGE_IP_FORMAT_ERROR						=12000
var	ERR_REMOTE_MANAGE_PORT_FORMAT_ERROR						=12001
var	ERR_REMOTE_MANAGE_PORT_OUT_OF_RANGE						=12002

var	ERR_DMZ_HOST_IP_ADDR									=13000

var	ERR_VS_PAGE_NUM_ERROR									=14000
var	ERR_VS_PORT_OUT_RANGE									=14001
var	ERR_VS_PORT_FORMAT_ERROR								=14002
var	ERR_VS_IP_ADDRESS										=14003
var	ERR_VS_RECORD_ALREADY_EXIST								=14004
var	ERR_VS_PROTOCOL_TYPE_ERROR								=14005
var	ERR_VS_RECORD_ALREADY_FULL								=14006

var	ERR_SPECIAL_APP_PUBLIC_PORT								=15000
var	ERR_SPECIAL_APP_DUPLICATE_PUBLIC_PORT					=15001
var	ERR_SPECIAL_APP_DUPLICATE_TAG_PORT						=15002
var	ERR_SPECIAL_APP_RECORD_ALREADY_FULL						=15003

var	ERR_DDNS_USER_NAME_EMPTY								=16000
var	ERR_DDNS_PWD_EMPTY										=16001
var	ERR_DDNS_USER_HAS_SPACE									=16002
var	ERR_DDNS_PWD_HAS_SPACE									=16003
var	ERR_DDNS_LIST_FULL										=16004
var	ERR_DDNS_LIST_INDEX_OUT_RANGE							=16005
var	ERR_DDNS_ENTRY_BE_DELETE								=16006

var	ERR_USER_NAME_LENGTH									=17000
var	ERR_USER_PWD_LENGTH										=17001
var	ERR_USER_NAME_ERROR										=17002
var	ERR_USER_PWD_ERROR										=17003
var	ERR_USER_PWD_INVALID_CHAR								=17004

var	ERR_SYS_TFTP_FAIL										=18000
var	ERR_SYS_TFTP_FILE_LENGTH								=18001
var	ERR_SYS_TFTP_SERVNOTFOUND								=18002
var	ERR_SYS_ERR_SOCKET										=18003
var	ERR_SYS_FAIL											=18004
var	ERR_SYS_FILE_VER										=18005

var	ERR_SESSION_LIMIT_TBL_FULL								=19000
var	ERR_SESSION_LIMIT_RECORD_ALREADY_FULL					=19001
var	ERR_SESSION_LIMIT_RECORD_ALREADY_EXIST					=19002

var	ERR_ARP_REC_IP_EXIST									=20000
var	ERR_ARP_FIXMAP_FULL										=20001
var	ERR_ARP_REC_IP_EXIST_ADD_SUCC							=20002
var	ERR_ARP_REC_IP_EXIST_ADD_FAIL							=20003
var	ERR_ARP_IP_EXIST_AND_FIXMAP_FULL						=20004
var	ERR_ARP_FIXMAP_FULL_IGNORE_OTHER_ENTRYS					=20005
var ERR_ARP_FIXMAP_MAC_ERR									=20006
//added by ZQQ 081006
var ERR_ARP_IP_SAME_AS_LANIP                                =20007

var	ERR_SYS_LOG_SYS_STATUS									=21000
var	ERR_SYS_LOG_SRV_ID										=21001
var	ERR_SYS_LOG_SRV_STATUS									=21002
var	ERR_SYS_LOG_SRV_ADDRESS									=21003
var	ERR_SYS_LOG_SRV_ADDR_EXIST								=21004
var	ERR_SYS_LOG_SRV_PORT									=21005
var	ERR_SYS_LOG_SETTING_EMERGENCY							=21006
var	ERR_SYS_LOG_SETTING_ALERT								=21007
var	ERR_SYS_LOG_SETTING_CRITICAL							=21008
var	ERR_SYS_LOG_SETTING_ERROR								=21009
var	ERR_SYS_LOG_SETTING_WARNING								=21010
var	ERR_SYS_LOG_SETTING_NOTICE								=21011
var	ERR_SYS_LOG_SETTING_INFORMATIONAL						=21012
var	ERR_SYS_LOG_SETTING_DEBUG								=21013
var	ERR_SYS_LOG_SETTING_EMPTY								=21014

var	ERR_FIREWALL_SYSLOG_SERVER_INVALID_ID					=22000
var	ERR_FIREWALL_SYSLOG_SERVER_NOT_DEFINED					=22001
var	ERR_FIREWALL_SCREEN_UNKNOWN_DEFENCE						=22002
var	ERR_FIREWALL_SCREEN_SCAN_THRESHOLD						=22003
var	ERR_FIREWALL_SCREEN_DOS_THRESHOLD						=22004

var	ERR_TDDP_UPLOAD_FILE_TOO_LONG							=23000
var	ERR_TDDP_UPLOAD_FILE_FORMAT_ERR							=23001
//added by ZQQ,08.05.19 the upload file is too big
var ERR_TDDP_UPLOAD_FILE_NAME_ERR                           =23002

var	ERR_COMMON_ERROR										=25000
var	ERR_TDDP_DOWNLOAD_FILE_TOO_LONG							=25001
var ERR_VS_RECORD_CONFLICT_REMOTE_WEB_PORT                  =25002

var	ERR_DST_HOUR											=26000
var	ERR_DST_DAY												=26001
var	ERR_DST_MONTH											=26002
var	ERR_DST_BEGIN_END										=26003

var	ERR_WLAN_CONFIG_BASE									=26100
var	ERR_WLAN_CONFIG_SECURITY								=26101
var	ERR_WLAN_CONFIG_KEY										=26102
var	ERR_WLAN_MAC_FILTER_PAGE_NUM_ERROR						=26103
var	ERR_WLAN_MAC_FILTER_RECORD_ALREADY_EXIST				=26104
var	ERR_WLAN_MAC_FILTER_RECORD_ALREADY_FULL					=26105
//合并陈岩无线部分
var ERR_IP_NOT_IN_THE_SAME_SUBNET                           =26106
var ERR_WLAN_SSID_LEN                                       =26107
var ERR_WLAN_REGION                                         =26108
var ERR_WLAN_CHANNEL_WIDTH                                  =26109
var ERR_WLAN_STATIC_RATE                                    =26110
var ERR_WLAN_MODE                                           =26111      
var ERR_WLAN_BROADCAST                                      =26112
var ERR_WLAN_MAC_ADDR_INVALID                               =26113  
var ERR_WLAN_RADIUS_IP_INVALID                              =26114
var ERR_WLAN_WPS_PIN_INVALID								=26115                                      
//qos
var ERR_QOS_TOTAL_EGRESS_100M								= 27000	/* ZJin 090903: make the err msg more detailedly */
var ERR_QOS_TOTAL_INGRESS_100M								= 27001
var ERR_QOS_TOTAL_EGRESS_1000M								= 27002
var ERR_QOS_TOTAL_INGRESS_1000M								= 27003
var ERR_QOS_NOBUF											= 27004/* 已经没有空间*/
var ERR_QOS_NOENT											= 27005/* 不存在在信息*/
var ERR_QOS_EXIST											= 27006/* 该信息已经存在*/
var ERR_QOS_USEDBW											= 27007/* 新的QoS 带宽小于已使用的带宽*/
var ERR_QOS_NOBW											= 27008/* 系统不能满足所要求的带宽*/
var ERR_QOS_BADRULE											= 27009/* 规则有交集*/
var ERR_QOS_TYPE											= 27010/* 错误的类型*/
var ERR_QOS_MAX												= 27011/*the max error code */
var ERR_QOS_INGRESS_BANDWIDTH								= 27012/*下行带宽总算大于系统提供总数*/
var ERR_QOS_EGRESS_BANDWIDTH								= 27013/*上行带宽总数大于系统提供总算*/

//家长控制
var ERR_PARENT_CTRL_FULL									=28000
var ERR_PARENT_CTRL_URLDESC									=28001
var ERR_PARENT_CTRL_SAME_MAC_WITH_PARENT					=28002
//过滤
var ERR_ACC_CTRL_HOST_FULL									=29000
var ERR_ACC_CTRL_TARGET_FULL								=29001
var ERR_ACC_CTRL_SCHEDULE_FULL								=29002
var ERR_ACC_CTRL_RULE_FULL									=29003
var ERR_ACC_CTRL_SAME_NAME									=29004
var ERR_ACC_CTRL_REFERED									=29005
var ERR_ACC_CTRL_RULE_CONFLICT								=29006
var ERR_ACC_PARTIAL_DEL										=29007
var ERR_ACC_DEL_NONE										=29008
var ERR_FILTER_MAC											=29009
var ERR_ACC_CTRL_HOST_IPSTART								=29010
var ERR_ACC_CTRL_HOST_IPEND									=29011
var ERR_ACC_CTRL_TARGET_IPSTART								=29012
var ERR_ACC_CTRL_TARGET_IPEND								=29013
var ERR_ACC_CTRL_HOST_IPSTART_NOT_IN_THE_SAME_SUBNET		=29014
var ERR_ACC_CTRL_HOST_IPEND_NOT_IN_THE_SAME_SUBNET			=29015

//ADSL ERROR
var ERR_ADSL_CONFIG	= 30000
var ERR_ADSL_PARAMETER = 30001
var ERR_LOAD_ADSL_CONFIG = 30002
//system mode ERROR
var ERR_SYSTEM_MODE	= 31000
var ERR_SYSTEM_MODE_CONFIG = 31001
// TC update error					
var ERR_UPDATE_TC_BRIDGE = 32000
var ERR_DSL_FIRMWARE_CHECKSUM = 32001

//USB Settings error
var ERR_NAS_ACCOUNT_DUPLICATE = 33000
var ERR_NAS_TOO_MANY_USER = 33001
var ERR_FTP_SHAREFOLDER_DUPLICATE = 33002
var ERR_FTP_TOO_MANY_SHAREFOLDER = 33003
var ERR_FTP_INVALID_PORT = 33004
                                      
var str_err = new Array();
str_err[ERR_NO_ERROR]					=	"有错误发生，请重试！"
str_err[ERR_PPPOE_FIXED_IP]				=	"IP地址错误，请重新输入。"
str_err[ERR_PPPOE_TIMING_SET]			=	"定时连接设置错误。"
//str_err[ERR_PPPOE_STRING_TOO_LONG]		=	"有错误发生，请重试！"
str_err[ERR_PPPOE_STRING_TOO_LONG]		=	"PPPOE密码或用户名字长度出错。"
str_err[ERR_PPPOE_USERNAME_TOO_LONG]	=	"上网帐号长度不得超过119个字符，请重新输入。"
str_err[ERR_PPPOE_PWD_TOO_LONG]			=	"上网密码长度不得超过119个字符，请重新输入。"
str_err[ERR_PPPOE_AUTO_OFF_WAITE_TIME]	=	"自动断线等待时间超出合法范围（10－99），请重新输入。"
str_err[ERR_PPPOE_LCP_MRU]				=	"MTU设置超出合法范围（576－1500），请重新输入。"
str_err[ERR_PPPOE_ECHO_REQ_INTERVAL]	=	"在线检测间隔时间错误。"
str_err[ERR_DHCP_SERVER_ADDR_POOL_ERROR]=	"IP地址池错误，请重新输入。"
str_err[ERR_DHCP_SERVER_GATEWAY_ERROR]	=	"网关错误，请重新输入。"
str_err[ERR_DHCP_SERVER_DNS_ERROR]		=	"首选DNS服务器地址错误，请重新输入。"
str_err[ERR_DHCP_SERVER_BAK_DNS_ERROR]	=	"备用DNS服务器地址错误，请重新输入。"
str_err[ERR_DHCP_SERVER_LEASE]			=	"地址租期超出范围（1-2880）。请重新输入。"
str_err[ERR_DHCP_SERVER_START_IP_ADDR]	=	"地址池开始地址错误，请重新输入。"
str_err[ERR_DHCP_SERVER_END_IP_ADDR]	=	"地址池结束地址错误，请重新输入。"
str_err[ERR_DHCP_SERVER_START_BIGGER_END]=	"地址池开始地址大于结束地址。"
str_err[ERR_DHCP_SERVER_ADD_RANGE]		=	"地址池范围不得大于256，请重新输入。"
str_err[ERR_FIX_MAP_MAC_ADDR_ERROR]		=	"MAC地址错误，请重新输入。"
str_err[ERR_FIX_MAP_IP_ADDR_ERROR]		=	"IP地址错误，请重新输入。"
str_err[ERR_FIX_MAP_REC_EXIST]			=	"静态地址分配条目已存在，请重新输入。"
str_err[ERR_FIX_MAP_PAGE_NUM_ERROR]		=	"静态地址分配页面号错误，请重新输入。"
str_err[ERR_FIX_MAP_RECORD_ALREADY_FULL]=	"静态地址分配列表已满。"
str_err[ERR_FIX_MAP_RECORD_MAC_ALREADY_EXIST]=	"MAC地址已被包含在其它静态地址分配条目中。"
str_err[ERR_FIX_MAP_RECORD_IP_ALREADY_EXIST]=	"IP地址已被包含在其它静态地址分配条目中。"
str_err[ERR_FIX_MAP_IP_EQUAL_LANIP]			=	"IP地址不能与LAN口IP地址相同。";
str_err[ERR_STATIC_ROUTR_ENABLE]		=	"有错误发生，请重试！"
str_err[ERR_STATIC_ROUTR_DESTINATION_IP]=	"目的IP地址错误，请重新输入。"
str_err[ERR_STATIC_ROUTR_SUBNETMASK_IP]	=	"子网掩码错误，请重新输入。"
str_err[ERR_STATIC_ROUTR_SUBNETMASK_DISMATCH_IP]="子网掩码和目的网络地址不匹配，请重新输入。"
str_err[ERR_STATIC_ROUTR_GATEWAY_IP]	=	"网关错误，请重新输入。"
str_err[ERR_STATIC_ROUTR_NOEMPTY]		=	"有错误发生，请重试！"
str_err[ERR_STATIC_ROUTR_DUPLICATION]	=	"静态路由表条目已存在，请重新输入。"
str_err[ERR_STATIC_ROUTR_DEFAULT_GATEWAY]=	"默认网关，请在网络参数菜单下进行设置。"
str_err[ERR_STATIC_ROUTR_NOT_SAME_NETWORK]=	"网关地址必须与LAN或WAN在同一子网。"
str_err[ERR_STATIC_ROUTR_CONFLICT_LAN_WAN]=	"静态路由条目与LAN口设置或WAN口设置冲突，请重新输入。"
str_err[ERR_STATIC_DEST_CONFLICT_LAN]	=	"目的网络地址不能与LAN口地址处于同一子网，请重新输入。"
str_err[ERR_STATIC_DEST_CONFLICT_WAN]	=	"目的网络地址不能处于WAN口地址所在的子网内部，请重新输入。"
str_err[ERR_STATIC_ROUTR_ALREADY_FULL]	=	"静态路由表已满！"
str_err[ERR_STATIC_ROUTR_SAVE]			=	"有错误发生，请重试！"
str_err[ERR_STATIC_ROUTR_OTHER]			=	"有错误发生，请重试！"

str_err[ERR_WAN_DOWN_BANDWIDTH]			=	"下行带宽超出允许范围，请重新输入（1-100000）。"
str_err[ERR_WAN_UP_BANDWIDTH]			=	"上行带宽超出允许范围，请重新输入（1-100000）。"
//qos
str_err[ERR_QOS_TOTAL_EGRESS_100M]		=	"上行总带宽超出允许范围，请重新输入（1-100000）。建议您设置为ISP分配带宽。";
str_err[ERR_QOS_TOTAL_INGRESS_100M]		=	"下行总带宽超出允许范围，请重新输入（1-100000）。建议您设置为ISP分配带宽。";
str_err[ERR_QOS_TOTAL_EGRESS_1000M]		=	"上行总带宽超出允许范围，请重新输入（1-1000000）。建议您设置为ISP分配带宽。";
str_err[ERR_QOS_TOTAL_INGRESS_1000M]	=	"下行总带宽超出允许范围，请重新输入（1-1000000）。建议您设置为ISP分配带宽。";
str_err[ERR_QOS_NOBW]					=	"系统不能满足所要求的带宽，请重新输入。"
str_err[ERR_QOS_BADRULE]				=	"设定的规则有交集，请重新输入。"


str_err[ERR_ARP_IP_SAME_AS_LANIP]       =	"禁止将LAN口IP与其它MAC地址绑定。"

str_err[ERR_NETWORK_MTU]				=	"MTU输入错误，请重新输入（576－1500）。"
str_err[ERR_LAN_IP_ERROR]				=	"LAN口IP地址错误，请重新输入。"
str_err[ERR_LAN_MASK_ERROR]				=	"LAN口子网掩码错误，请重新输入。"
str_err[ERR_WAN_IP_ERROR]				=	"WAN口IP地址错误，请重新输入。"
str_err[ERR_WAN_MASK_ERROR]				=	"WAN口子网掩码错误，请重新输入。"
str_err[ERR_WAN_DNS_ERROR]				=	"首选DNS服务器地址错误，请重新输入。"
str_err[ERR_WAN_BACKDNS_ERROR]			=	"备用DNS服务器地址错误，请重新输入。"
str_err[ERR_WAN_GATE_ERROR]				=	"WAN口网关错误，请重新输入。"
str_err[ERR_WAN_LAN_CONFLICT]			=	"WAN口IP地址和LAN口IP地址不能处于同一子网，请重新输入。"
str_err[ERR_WAN_TYPE]					=	"错误的网络连接类型，请选择正确的连接类型。"
str_err[ERR_LAN_IP_SET]					=	"有错误发生，请重试！"
str_err[ERR_LAN_MASK_SET]				=	"有错误发生，请重试！"
str_err[ERR_WAN_IP_SERVER]				=	"WAN口IP错误。"
str_err[ERR_WAN_IP_SET]					=	"有错误发生，请重试！"
str_err[ERR_WAN_MASK_SET]				=	"有错误发生，请重试！"
str_err[ERR_WAN_DNS_SET]				=	"有错误发生，请重试！"
str_err[ERR_WAN_GATE_SET]				=	"有错误发生，请重试！"
str_err[ERR_WAN_MAC_ADDR]				=	"MAC地址错误，请重新输入。"
str_err[ERR_WAN_MAC_DUPLICATE]			=	"重复的MAC地址。"
str_err[ERR_WAN_MAC_EQ_LAN_MAC]			=	"WAN口MAC地址和LAN口MAC地址冲突。"
str_err[ERR_SNTP_MONTH]					=	"时间输入错误，请重新输入（月的范围为从01到12）。"
str_err[ERR_SNTP_DAY]					=	"时间输入错误，请重新输入（日的范围为从01到31）。"
str_err[ERR_SNTP_YEAR]					=	"时间输入错误，请重新输入（年的范围为从1970到2037）。"
str_err[ERR_SNTP_HOUR]					=	"时间输入错误，请重新输入（时的范围为从00到23）。"
str_err[ERR_SNTP_MINUTE]				=	"时间输入错误，请重新输入（分的范围为从00到59）。"
str_err[ERR_SNTP_SECOND]				=	"时间输入错误，请重新输入（秒的范围为从00到59）。"
str_err[ERR_SNTP_TIME_SET]				=	"时间设置失败，请重试。"
str_err[ERR_SNTP_TIMEZONE]				=	"时区错误，请选择正确的时区。"
str_err[ERR_SNTP_GET_GMT_FAILED]		=	"获取网络时间错误，请检查是否正确连接到网络。"
str_err[ERR_MORNITOR_PORT_ACTIVE_PORT]	=	"有错误发生，请重试！"
str_err[ERR_MORNITOR_PORT_PASSIVE_PORT]	=	"有错误发生，请重试！"
str_err[ERR_MORNITOR_PORT_EQUAL_PORT]	=	"有错误发生，请重试！"
str_err[ERR_MORNITOR_NONE_PORT]			=	"有错误发生，请重试！"
str_err[ERR_TFTP_OVER_FILE_LEN]			=	"文件名超出长度，允许的文件名最大长度是20字符。"
str_err[ERR_TFTP_IP_ERROR]				=	"TFTP服务器错误。"
str_err[ERR_FIREWALL_START_TIME_FORMAT_ERROR]=	"开始时间错误，请以格式hhmm输入24小时制时间。 "
str_err[ERR_FIREWALL_END_TIME_FORMAT_ERROR]=	"结束时间错误，请以格式hhmm输入24小时制时间。"
str_err[ERR_FIREWALL_TIME_START_BIGGER_END]=	"开始时间不能晚于结束时间，请重新输入。"
str_err[ERR_FIREWALL_LAN_IP_FORMAT_ERROR]=	"LAN口IP地址错误，请重新输入。"
str_err[ERR_FIREWALL_LAN_PORT_FORMAT_ERROR]=	"LAN口端口号超出允许范围（1-65535），请重新输入。"
str_err[ERR_FIREWALL_WAN_IP_FORMAT_ERROR]=	"WAN口IP地址错误，请重新输入。"
str_err[ERR_FIREWALL_WAN_PORT_FORMAT_ERROR]=	"WAN口端口号超出允许范围（1-65535），请重新输入。"
str_err[ERR_FIREWALL_PROTOCOL_TYPE_ERROR]=	"协议选择错误，请重试。"
str_err[ERR_FIREWALL_RECORD_ALREADY_EXIST]=	"条目已存在。"
str_err[ERR_FIREWALL_IP_RECORD_ALREADY_FULL]=	"IP地址过滤表已满。"
str_err[ERR_FIREWALL_DOMAIN_NAME_LEN_OVER]=	"域名长度超长，请重新输入。"
str_err[ERR_FIREWALL_DOMAIN_NAME_ERROR]	=	"域名不合法，请重新输入。"
str_err[ERR_FIREWALL_DOMAIN_IS_SUBSET]	=	"域名存在包含关系，已包含另一条目或已被另一条目包含，请检查并重新输入。"
str_err[ERR_FIREWALL_DOMAIN_RECORD_ALREADY_FULL]=	"域名过滤表已满。"
str_err[ERR_FIREWALL_TIME_NOT_FULL]		=	"请同时输入开始时间和结束时间。"
str_err[ERR_FIREWALL_TIME_FORMAT_ERROR]	=	"时间格式错误，请以hhmm格式输入24小时制时间。"
str_err[ERR_FIREWALL_WZD_TIME_ALREADY_EXIST]=	"时间范围与其它条目冲突。"
str_err[ERR_FIREWALL_WZD_TIME_IS_SUBSET]=	"时间范围已被其它条目包含。"
str_err[ERR_FIREWALL_WZD_IP_FORMAT_ERROR]=	"地址错误，请重新输入IP地址或IP地址段或域名。<br>如果输入的是IP地址段，请确保起始IP和结束IP在同一IP地址段，并且可用。"
str_err[ERR_FIREWALL_WZD_ADDR_ALREADY_EXIST]=	"IP地址或域名冲突。"
str_err[ERR_FIREWALL_WZD_PORT_FORMAT_ERROR]=	"端口号错误，<br>请输入1-65535之间的数字，或以“-”连接的端口段，端口或端口段之间以“,”分隔。<br><br>"
str_err[ERR_FIREWALL_WZD_PORT_IS_SUBSET]=	"端口号已被其它条目使用。"
str_err[ERR_MAC_FILTER_PAGE_NUM_ERROR]	=	"MAC过滤表页错误。"
str_err[ERR_MAC_FILTER_RECORD_ALREADY_EXIST]=	"条目已存在，请重新输入。"
str_err[ERR_MAC_FILTER_RECORD_ALREADY_FULL]=	"MAC地址过滤表已满。"
str_err[ERR_MAC_FILTER_FORMAT_ERROR]	=	"MAC地址错误，请重新输入。"
str_err[ERR_REMOTE_MANAGE_IP_FORMAT_ERROR]=		"IP地址错误，请重新输入。"
str_err[ERR_REMOTE_MANAGE_PORT_FORMAT_ERROR]=	"端口号错误，请重新输入。"
str_err[ERR_REMOTE_MANAGE_PORT_OUT_OF_RANGE]=	"远程管理端口号超出范围（1-65535）或为浏览器不支持的端口（21、25、110等），请重新输入。"
str_err[ERR_DMZ_HOST_IP_ADDR]			=	"DMZ主机错误，请重新输入。"
str_err[ERR_VS_PAGE_NUM_ERROR]			=	"虚拟服务器表页错误。"
str_err[ERR_VS_PORT_OUT_RANGE]			=	"端口号超出范围（1-65535），请重新输入。"
str_err[ERR_VS_PORT_FORMAT_ERROR]		=	"端口号可以是数字或者数字范围（以“-”连接），请重新输入。"
str_err[ERR_VS_IP_ADDRESS]				=	"IP地址错误，请重新输入。"
str_err[ERR_VS_RECORD_ALREADY_EXIST]	=	"条目已存在或端口号已被其它条目使用，请重新输入。"
str_err[ERR_VS_PROTOCOL_TYPE_ERROR]		=	"协议类型错误，请重新选择。"
str_err[ERR_VS_RECORD_ALREADY_FULL]		=	"虚拟服务器表已满。"
str_err[ERR_SPECIAL_APP_PUBLIC_PORT]	=	"开放端口错误，请重新输入。"
str_err[ERR_SPECIAL_APP_DUPLICATE_PUBLIC_PORT]=	"开放端口与已存在条目冲突，请重新输入。<br>两个条目不能设置相同的开放端口。"
str_err[ERR_SPECIAL_APP_DUPLICATE_TAG_PORT]=	"触发条件与已存在条目冲突，请重新输入。<br>两个条目不能将触发协议和触发端口都设为相同。"
str_err[ERR_SPECIAL_APP_RECORD_ALREADY_FULL]=	"特殊应用程序表已满。"
str_err[ERR_DDNS_USER_NAME_EMPTY]		=	"用户名不能为空，请重新输入。"
str_err[ERR_DDNS_PWD_EMPTY]				=	"密码不能为空，请重新输入。"
str_err[ERR_DDNS_USER_HAS_SPACE]		=	"用户名不能包含空格，请重新输入。"
str_err[ERR_DDNS_PWD_HAS_SPACE]			=	"密码不能包含空格，请重新输入。"
str_err[ERR_DDNS_LIST_FULL]				=	"DDNS条目已满。"
str_err[ERR_DDNS_LIST_INDEX_OUT_RANGE]	=	"条目索引超出范围。"
str_err[ERR_DDNS_ENTRY_BE_DELETE]		=	"条目已被删除。"
str_err[ERR_USER_NAME_LENGTH]			=	"用户名长度超过15个字符，请重新输入。"
str_err[ERR_USER_PWD_LENGTH]			=	"密码长度超过15个字符，请重新输入。"
str_err[ERR_USER_NAME_ERROR]			=	"旧用户名错误，请重新输入。"
str_err[ERR_USER_PWD_ERROR]				=	"旧密码错误，请重新输入。"
str_err[ERR_USER_PWD_INVALID_CHAR]		=	"用户名或密码包含非法字符，请重新输入。"
str_err[ERR_SYS_TFTP_FAIL]				=	"有错误发生，请重试！"
str_err[ERR_SYS_TFTP_FILE_LENGTH]		=	"上传文件长度错误，请检查文件并重试。"
str_err[ERR_SYS_TFTP_SERVNOTFOUND]		=	"Upgrade unsuccessfully, make sure that you have launched the TFTP server."
str_err[ERR_SYS_ERR_SOCKET]				=	"Upgrade unsuccessfully, make sure that you have launched the TFTP server and the upgraded file was in correct directory."
str_err[ERR_SYS_FAIL]					=	"文件传输错误。"
str_err[ERR_SYS_FILE_VER]				=	"上传的文件版本与机型不符。"
str_err[ERR_SESSION_LIMIT_TBL_FULL]		=	"有错误发生，请重试！"
str_err[ERR_SESSION_LIMIT_RECORD_ALREADY_FULL]=	"有错误发生，请重试！"
str_err[ERR_SESSION_LIMIT_RECORD_ALREADY_EXIST]="有错误发生，请重试！"

str_err[ERR_ARP_REC_IP_EXIST]			=	"条目与已分配的静态条目冲突。"
str_err[ERR_ARP_FIXMAP_FULL]			=	"静态列表已满，添加失败。"
str_err[ERR_ARP_REC_IP_EXIST_ADD_SUCC]		=	"忽略与静态条目冲突条目，成功添加其他条目。"
str_err[ERR_ARP_REC_IP_EXIST_ADD_FAIL]		=	"所有欲添加条目均与静态条目冲突，添加失败。"
str_err[ERR_ARP_IP_EXIST_AND_FIXMAP_FULL]	=	"静态列表已满。"
str_err[ERR_ARP_FIXMAP_FULL_IGNORE_OTHER_ENTRYS]=	"静态列表已添加满，忽略多余条目。"
str_err[ERR_ARP_FIXMAP_MAC_ERR]=	  "MAC地址错误，请重新输入。"

str_err[ERR_SYS_LOG_SYS_STATUS]			=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SRV_ID]				=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SRV_STATUS]			=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SRV_ADDRESS]		=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SRV_ADDR_EXIST]		=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SRV_PORT]			=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_EMERGENCY]	=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_ALERT]		=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_CRITICAL]	=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_ERROR]		=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_WARNING]	=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_NOTICE]		=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_INFORMATIONAL]=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_DEBUG]		=	"有错误发生，请重试！"
str_err[ERR_SYS_LOG_SETTING_EMPTY]		=	"有错误发生，请重试！"
str_err[ERR_FIREWALL_SYSLOG_SERVER_INVALID_ID]=	"有错误发生，请重试！"
str_err[ERR_FIREWALL_SYSLOG_SERVER_NOT_DEFINED]=	"有错误发生，请重试！"
str_err[ERR_FIREWALL_SCREEN_UNKNOWN_DEFENCE]=	"有错误发生，请重试！"
str_err[ERR_FIREWALL_SCREEN_SCAN_THRESHOLD]=	"有错误发生，请重试！"
str_err[ERR_FIREWALL_SCREEN_DOS_THRESHOLD]=	"有错误发生，请重试！"
str_err[ERR_TDDP_UPLOAD_FILE_TOO_LONG]	=	"上传文件大小太大。 "
str_err[ERR_TDDP_UPLOAD_FILE_FORMAT_ERR]=	"文件格式错误。"
str_err[ERR_TDDP_UPLOAD_FILE_NAME_ERR]=	"文件名太长，文件名长度必须小于64字节。"
str_err[ERR_COMMON_ERROR]				=	"有错误发生，请重试！"
str_err[ERR_DST_HOUR]					=	"DST时间错误，请重新输入。"
str_err[ERR_DST_DAY]					=	"DST时间错误，请重新输入。"
str_err[ERR_DST_MONTH]					=	"DST时间错误，请重新输入。"
str_err[ERR_DST_BEGIN_END]				=	"开始时间与结束时间不能相同。"
str_err[ERR_TDDP_DOWNLOAD_FILE_TOO_LONG]=	"下载的文件太大。"
str_err[ERR_VS_RECORD_CONFLICT_REMOTE_WEB_PORT] = "虚拟服务器端口与远程Web管理端口冲突。"
str_err[ERR_WLAN_CONFIG_BASE]			=	"无线设置错误。"
str_err[ERR_WLAN_CONFIG_SECURITY]		=	"无线安全设置错误。"
str_err[ERR_WLAN_CONFIG_KEY]			=	"WEP密钥错误。"
str_err[ERR_WLAN_MAC_FILTER_PAGE_NUM_ERROR]=	"无线MAC过滤表页不存在，请重试。"
str_err[ERR_WLAN_MAC_FILTER_RECORD_ALREADY_EXIST]=	"条目已存在，请重新输入。"
str_err[ERR_WLAN_MAC_FILTER_RECORD_ALREADY_FULL]=	"无线MAC地址过滤表已满。"
//add by zhouqiqiu 2007-10-2
str_err[ERR_IP_NOT_IN_THE_SAME_SUBNET]          =   "IP地址和当前LAN不在同一子网。"
str_err[ERR_WLAN_SSID_LEN]                      =   "SSID长度错误。"
str_err[ERR_WLAN_REGION]                        =   "地区码错误。"
str_err[ERR_WLAN_CHANNEL_WIDTH]                 =   "频带宽度错误。"
str_err[ERR_WLAN_STATIC_RATE]                   =   "静态速率错误。"
str_err[ERR_WLAN_MODE]                          =   "无线模式错误。"
str_err[ERR_WLAN_BROADCAST]                     =   "广播错误。"
str_err[ERR_WLAN_MAC_ADDR_INVALID]              =   "MAC地址错误，请重新输入。"
str_err[ERR_WLAN_RADIUS_IP_INVALID]             =   "Radius服务器IP非法。"
str_err[ERR_WLAN_WPS_PIN_INVALID]				=	"PIN码错误。"
str_err[ERR_SERVER_IP_ERROR]					=	"服务器IP地址错误，请重新输入。"


//家长控制
str_err[ERR_PARENT_CTRL_FULL]					=	"家长控制列表已满。"
str_err[ERR_PARENT_CTRL_URLDESC]				=	"有重复的网站列表命名。"
str_err[ERR_PARENT_CTRL_SAME_MAC_WITH_PARENT]	=	"小孩PC的MAC不能与家长PC的MAC相同。"

//过滤
str_err[ERR_ACC_CTRL_HOST_FULL]					=	"主机列表已满。"
str_err[ERR_ACC_CTRL_TARGET_FULL]				=	"访问目标列表已满。"
str_err[ERR_ACC_CTRL_SCHEDULE_FULL]				=	"日程计划列表已满。"
str_err[ERR_ACC_CTRL_RULE_FULL]					=	"访问控制规则管理列表已满。"
str_err[ERR_ACC_CTRL_SAME_NAME]					=	"有重复的列表命名。"
str_err[ERR_ACC_CTRL_REFERED]					=	"条目被引用，不能删除。"
str_err[ERR_ACC_CTRL_RULE_CONFLICT]				=	"存在重复的条目。"
str_err[ERR_ACC_PARTIAL_DEL]					=	"部分条目被引用，不能删除，已删除未被引用的条目。"
str_err[ERR_ACC_DEL_NONE]						=	"所有条目均被引用，不能删除。"
str_err[ERR_FILTER_MAC]							=	"MAC地址输入错误。"
str_err[ERR_ACC_CTRL_HOST_IPSTART]				=	"起始IP地址输入错误。"
str_err[ERR_ACC_CTRL_HOST_IPEND]				=	"结束IP地址输入错误。"
str_err[ERR_ACC_CTRL_TARGET_IPSTART]			=	"起始IP地址输入错误。"
str_err[ERR_ACC_CTRL_TARGET_IPEND]				=	"结束IP地址输入错误。"
str_err[ERR_ACC_CTRL_HOST_IPSTART_NOT_IN_THE_SAME_SUBNET] = "起始IP地址必须与LAN在同一子网。";
str_err[ERR_ACC_CTRL_HOST_IPEND_NOT_IN_THE_SAME_SUBNET] = "结束IP地址必须与LAN在同一子网。";


//ADSL ERROR
str_err[ERR_ADSL_CONFIG]	=	"配置错误"
str_err[ERR_ADSL_PARAMETER] = "参数错误"
str_err[ERR_LOAD_ADSL_CONFIG] = "载入配置错误"

//system mode ERROR
str_err[ERR_SYSTEM_MODE] = "上网类型错误"
str_err[ERR_SYSTEM_MODE_CONFIG] = "参数错误"

// TC update error					
str_err[ERR_UPDATE_TC_BRIDGE] = "tc 升级错误"
str_err[ERR_DSL_FIRMWARE_CHECKSUM] = "DSL升级固件md5校验和错误"
str_err[ERR_MAC_WAN_EQUAL_PC] = "在无线ADSL桥或无线路由模式下，不能直接克隆管理PC的MAC地址"

//nas
str_err[ERR_NAS_ACCOUNT_DUPLICATE]				=	"用户名不能重复。";
str_err[ERR_FTP_INVALID_PORT]					=	"该端口号可能被路由器上其他程序占用，请选择其他端口。";
str_err[ERR_NAS_TOO_MANY_USER]					=	"用户过多。";
str_err[ERR_FTP_SHAREFOLDER_DUPLICATE]			=	"共享文件夹不能重名。";
str_err[ERR_FTP_TOO_MANY_SHAREFOLDER]			=	"共享文件夹过多。";

