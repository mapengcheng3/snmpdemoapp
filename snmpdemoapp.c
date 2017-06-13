#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-include.h>
#include <string.h>
int main(int argc, char const *argv[])
{
	/* code */
	/**
	结构体netsnmp中记录了SNMP的会话信息
	第一个变量需要填充准备会话的信息
	第二个为一指针用于记录库返回的信息
	*/
	netsnmp_session session, **ss;
	//该结构体中定义了远程主机所有的信息
	netsnmp_pdu *pdu;
	//该结构体记录了远程主机返回的PDU消息
	netsnmp_pdu *response;
	//记录oid节点位置信息
	oid anOID[MAX_OID_LEN];
	size_t anOID_len;
	//变量绑定列表(为list数据结构)也就是需要操作的数据
	netsnmp_variable_list *vars;
	int status;
	int count = 1;

	/*
	初始化SNMP库
	初始化互斥量，MIB解析，传输层
	调试信息的初始化，解析配置文件的初始化（netsnmp_ds_register_config),各句柄的初始化
	定时器的初始化，读取配置文件
	*/
	init_snmp("snmpdemoapp");

	//session初始化，包括初始化目的地，SNMP版本协议，认证机制
	//初始化会话结构体，不涉及任何MIB文件处理

	snmp_sess_init(&session);
	//设置会话结构体：目标地址；可以为其他有效的网络地址
	session.peername = strdup("localhost");
	//使用SNMPv1版本
	session.version = SNMP_VERSION_1;
	//设置共同体
	session.community = "public";
	session.community_len = strlen(session.community);

	ss = snmp_open(&session);
	if(!ss){
		snmp_sess_perror("snmpdemoapp", &session);
		exit(1);
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	anOID_len = MAX_OID_LEN;//这个宏的值为128

	if(!snmp_parse_oid("system.sysDescr.0", anOID, &anOID_len)){
		snmp_perror(".1.3.6.1.2.1.1.1.0");
		exit(1);
	}

	snmp_add_null_var(pdu, anOID, anOID_len);
	status = snmp_synch_response(ss,pdu,&response);

	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
		for (vars = response->variables;vars;vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);
		for (vars = response->variables;vars;vars = vars->next_variable)
		{
			if (vars->type == ASN_OCTET_STR) {
				char *sp = (char *)malloc(1 + vars->val_len);
				memcpy(sp, vars->val.string, vars->val_len);
				sp[vars->val_len] = '\0';
				printf("value #%d is a string: %s\n",count++, sp);
				free(sp);
			} else {
				printf("value #%d is not a string! ACK\n",count++);
			}
		}
	} else {
		if (status == STAT_SUCCESS)
			fprintf(stderr, "Error in packet\nReason:%s\n", snmp_errstring(response->errstat));
		else if (status == STAT_TIMEOUT)
			fprintf(stderr, "Timeout: no response from %s\n", session.peername);
		else
			snmp_sess_perror("snmpdemoapp",ss);

	}
	if (response)
		snmp_free_pdu(response);
	snmp_close(ss);
	return 0;
}
