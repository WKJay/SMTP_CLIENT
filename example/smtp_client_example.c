/*************************************************
 Copyright (c) 2019
 All rights reserved.
 File name:     smtp_client_example.c
 Description:   smtp发送邮件示例邮件
 History:
 1. Version:    V1.0.0
    Date:       2019-10-14
    Author:     wangjunjie
    Modify:     
2. Version:     V1.0.1
    Date:       2019-10-14
    Author:     wangjunjie
    Modify:     添加多收件人功能
*************************************************/
#include "smtp_client.h"
#include "rtthread.h"

//若使用TLS加密则需要更大的堆栈空间
#ifdef SMTP_CLIENT_USING_TLS
#define SMTP_CLIENT_THREAD_STACK_SIZE 4096
#else
#define SMTP_CLIENT_THREAD_STACK_SIZE 2048
#endif

/*
 *邮件信息相关宏定义
 */
//smtp 服务器域名
#define SMTP_SERVER_ADDR "smtp.qq.com"
//smtp 服务器端口号
#define SMTP_SERVER_PORT "25"
//smtp 登录用户名
#define SMTP_USERNAME    ""
//smtp 登录密码（或凭证）
#define SMTP_PASSWORD    ""
//邮件主题
#define SMTP_SUBJECT     "SMTP TEST"


//邮件内容
char *content = "THIS IS SMTP TEST\r\n"
                "HELLO SMTP\r\n"
                "--------------------------------------\r\n"
                "based on --->   RT-Thread\r\n"
                "based on ---> SMTP_CLIENT\r\n";
                
void smtp_thread(void *param)
{
    //手动延时等待网络初始化成功
    rt_thread_delay(10000);

    //初始化smtp客户端
    smtp_client_init();
    //设置服务器地址
    smtp_set_server_addr(SMTP_SERVER_ADDR, ADDRESS_TYPE_DOMAIN, SMTP_SERVER_PORT);
    //设置服务器认证信息
    smtp_set_auth(SMTP_USERNAME, SMTP_PASSWORD);
    
    //添加收件人1
    smtp_add_receiver("abc@test.com");
    //添加收件人2
    smtp_add_receiver("def@test.com");
    //添加收件人3
    smtp_add_receiver("hij@test.com");
    //删除收件人2
    smtp_delete_receiver("def@test.com");

    //发送邮件
    rt_kprintf("\r\n[smtp]: O > start to send mail\r\n");
    if (smtp_send_mail(SMTP_SUBJECT, content) == 0)
    {
        //发送成功
        rt_kprintf("\r\n[smtp]: O > send mail success!\r\n");
    }
    else
    {
        //发送失败
        rt_kprintf("\r\n[smtp]: X > send mail fail!\r\n");
    }
}

int smtp_thread_entry(void)
{
    rt_thread_t smtp_client_tid;
    //创建邮件发送线程（如果选择在主函数中直接调用邮件发送函数，需要注意主函数堆栈大小，必要时调大）
    smtp_client_tid = rt_thread_create("smtp", smtp_thread, RT_NULL, SMTP_CLIENT_THREAD_STACK_SIZE, 20, 5);
    if (smtp_client_tid != RT_NULL)
    {
        rt_thread_startup(smtp_client_tid);
    }
    return RT_EOK;
}
INIT_APP_EXPORT(smtp_thread_entry);
