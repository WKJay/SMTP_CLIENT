# SMTP_CLIENT 

#### 当前版本：V1.0.2


|版本|连接|
|---|---|
|V1.0.0|[点我查看](doc/readme_V1.0.0.md)|

##### 新增功能

1. 支持设置多个收件人
2. 支持删除指定收件人
3. 支持附件发送（需要文件系统）

##### API变更

1. 新版中需要调用 `smtp_add_receiver` 函数添加邮件的收件人，当使用多个收件人时只需多次调用该函数即可。
2. 新版中 `smtp_send_mail` 函数去掉了发送者邮箱地址与接收者邮箱地址两个参数。发送者邮箱地址必须与服务器用户名相同，在设置服务器用户名后系统自动设置，接收者邮箱通过 `smtp_add_receiver` 进行设置。
3. 新版加入 `smtp_add_attachment`与`smtp_clear_attachments`接口，用于添加与清空附件，附件可以添加多个，清空附件时会清空所有之前添加的附件。

------------------------------------------------------------------

## 简介

这是一个基于RT-Thread的SMTP软件包，其支持普通的25端口，同时也支持465和587这两个加密端口。该软件包的使用非常简单方便，如果是基于RT-Thread操作系统，则无需进行任何移植操作即可使用，且仅需调用几个简单的接口即可实现不同端口的邮件发送功能。

## 特性

- 支持25端口
- 支持加密功能，支持465,587端口。（有些邮件服务器可能不支持其中的某个端口，用户使用前需了解自己所选用的邮件服务器支持哪个端口的smtp功能）
- 使用简单，无需了解SMTP协议，设置好一些必要参数后仅需一个接口即可实现邮件发送。

## 软件包使用说明

### 准备工作
 
#### Env 配置说明

首先需要下载 SMTP_CLIENT 软件包，并将软件包加入到项目中。在 BSP 目录下使用 menuconfig 命令打开 Env 配置界面，在 `RT-Thread online packages → IoT - internet of things` 中选择 SMTP_CLIENT 软件包，具体路径如下：

```C

RT-Thread online packages
    IoT - internet of things  --->
         [*] smtp_client:smtp client package for rt-thread  --->
                Version (latest) --->
            [*] use 465/587 port(encrypted port)
            [ ] enable debug log information
                smtp_client Options --->
                    [*] smtp client example
                    [*] enable attachment

```

- **Version：** 配置软件版本
- **use 465/587 port(encrypted port):** 使用加密端口，选中后会将 **mbedtls** 软件包加入编译，同时开启 465和587 两个加密端口的支持。
- **enable debug log information：** 使能调试打印信息
- **smtp client example：** 加入示例文件
- **enable attachment：** 启用附件

**注意：加入示例文件后不能直接下载使用，默认示例中缺少SMTP的个人参数，需要用户补全自己的用户名密码及接收方邮箱等信息！**

#### 注意事项

 - 开启加密功能后会占用比较大的RAM空间，请根据自己使用的硬件平台决定是否选用加密。并且适当调大调用发送功能的线程的堆栈大小。（推荐大于8192）
 - 有些邮件服务器不支持某个加密端口或者默认关闭，使用者需要确认自己选用的邮件服务器所支持的端口，并且确认已经打开邮件服务器的SMTP功能。
 - 若用户在使用的过程中出现加密有关的错误，请参照 RT-Thread **mbedtls** 软件包的说明文档。

 ### 使用说明

 #### 使用步骤

 1. 调用 `smtp_client_init` 函数初始化 smtp_client 客户端
 2. 调用 `smtp_set_server_addr` 函数设置服务器的地址及端口
 3. 调用 `smtp_set_auth` 函数设置服务器认证信息
 4. 调用 `smtp_add_receiver` 函数添加收件人地址
 5. 调用 `smtp_add_attachment` 函数添加附件（可选）
 5. 调用 `smtp_send_mail` 函数发送邮件

 #### API详解

 ##### 1、初始化SMTP客户端

 ```C

 void smtp_client_init(void);
 
 ```

该函数主要用于初始化 smtp 会话结构。

##### 2、设置SMTP服务器地址及端口

```C

int smtp_set_server_addr(const char *server_addr, uint8_t addr_type, const char *port);

```

|参数|说明|
|---|---|
|server_addr|服务器地址|
|addr_type|地址类型（域名或IP）|
|port|端口|

|返回值|说明|
|----|----|
|0|设置成功|
|-1|设置失败|

该函数用于设置 smtp 服务器地址及端口，地址类型为域名类型和IP类型，分别对应宏 `ADDRESS_TYPE_DOMAIN` 与 ` ADDRESS_TYPE_IP` .**需要注意的是，由于时间仓促及其需求不是很大，目前仅支持域名连接，但如果有需求，在后续版本中会加入IP连接。当然程序中已预留接口，需求紧的用户可使用接口进行拓展**。

##### 3、设置 smtp 服务器认证信息

```C

int smtp_set_auth(const char *username, const char *password);

```

|参数|说明|
|---|---|
|username|服务器用户名|
|password|认证密码或凭据|

|返回值|说明|
|----|----|
|0|设置成功|
|-1|设置失败|

该函数用于设置 smtp 服务器的认证信息，需要注意有些服务器需要用 **凭据** 而非用户登录邮箱时的密码进行认证，用户在连接服务器时需要确认自己所用服务器的认证方式。

##### 4、添加收件人

```C

int smtp_add_receiver(char *receiver_addr);

```

|参数|说明|
|---|---|
|receiver_addr|收件人邮箱地址|

|返回值|说明|
|----|----|
|0|添加成功|
|-1|添加失败|

在邮件发送前需要调用该函数添加收件人，若需要将邮件发送给多个收件人，则仅需多次调用该函数并传入不同的参数即可。

##### 5、删除收件人

```C

int smtp_delete_receiver(char *receiver_addr);

```

|参数|说明|
|---|---|
|receiver_addr|收件人邮箱地址|

|返回值|说明|
|----|----|
|0|删除成功|
|-1|删除失败|

若当前有多个收件人的情况下想要删除某个特定的收件人，仅需调用该接口并传入待删除的收件人邮箱即可。

##### 6、发送邮件

```C

int smtp_send_mail(char *subject, char *body);

```

|参数|说明|
|---|---|
|subject|主题|
|body|内容|

|返回值|说明|
|----|----|
|0|发送成功|
|-1|发送失败|

该函数为邮件发送函数，在用户设置好服务器的连接参数后，可以直接调用该函数进行邮件的发送。

##### 7、添加附件

```C

int smtp_add_attachment(char *file_path, char *file_name)

```

|参数|说明|
|---|---|
|file_path|附件的文件路径|
|file_name|附件名|

|返回值|说明|
|----|----|
|0|添加成功|
|-1|添加失败|

用户可以自定义附件名，无需与文件路径中的文件名相同，在邮件中附件的名字总是为该函数中设置的附件名。

##### 8、清空附件

```C

void smtp_clear_attachments(void)

```

调用该函数可以清除所有添加的附件。

 #### 宏配置说明

若用户在使用过程中发现默认的配置无法满足自身的使用需求，用户可以进入 `smtp_client_private.h` 文件对相关宏定义参数进行配置：

|宏|说明|
|---|---|
|SMTP_MAX_ADDR_LEN|邮箱地址最大长度|
|SMTP_MAX_AUTH_LEN|认证信息最长度|
|SMTP_SEND_CMD_MAX_LEN|SMTP指令发送最大长度|
|SMTP_SEND_DATA_HEAD_MAX_LENGTH|邮件头最大长度|
|SMTP_SEND_DATA_MAX_LEN|邮件内容最大长度|
|SMTP_RESPONSE_MAX_LEN|服务器响应数据最大长度|

一般情况下，用户需要根据自己内容的大小对 `SMTP_SEND_DATA_MAX_LEN` 进行配置即可。

#### 使用例程

加入例程后需要在命令行中输入 smtp_test 指令开启邮件发送，为了防止频繁发送，例程限制了最小发送间隔为30s，在发送成功后的30s内输入测试指令均无效。

```C

/*************************************************
 Copyright (c) 2019
 All rights reserved.
 File name:     smtp_client_example.c
 Description:   smtp发送邮件示例邮件
 History:
 1. Version:    V1.0.0
    Date:       2019-10-14
    Author:     WKJay
    Modify:     
2. Version:     V1.0.1
    Date:       2019-10-14
    Author:     WKJay
    Modify:     添加多收件人功能
    
3. Version:    V1.0.2
    Date:       2020-06-22
    Author:     WKJay
    Modify:     增加附件功能
*************************************************/
#include "smtp_client.h"
#include "rtthread.h"

//若使用TLS加密则需要更大的堆栈空间
#ifdef SMTP_CLIENT_USING_TLS
#define SMTP_CLIENT_THREAD_STACK_SIZE 8192
#else
#define SMTP_CLIENT_THREAD_STACK_SIZE 4096
#endif

#define DBG_ENABLE
#define DBG_LEVEL 3
#define DBG_COLOR
#define DBG_SECTION_NAME "SMTP_EXAMPLE"
#include "rtdbg.h"

/*
 *邮件信息相关宏定义
 */
//smtp 服务器域名
#define SMTP_SERVER_ADDR "smtp.163.com"
//smtp 服务器端口号
#define SMTP_SERVER_PORT "25"
//smtp 登录用户名
#define SMTP_USERNAME ""
//smtp 登录密码（或凭证）
#define SMTP_PASSWORD ""
//邮件主题
#define SMTP_SUBJECT "SMTP TEST"

//邮件内容
char *content = "THIS IS SMTP TEST\r\n"
                "HELLO SMTP\r\n"
                "--------------------------------------\r\n"
                "based on --->   RT-Thread\r\n"
                "based on ---> SMTP_CLIENT\r\n";

uint8_t send_enable = 0;

void smtp_thread(void *param)
{
    //初始化smtp客户端
    smtp_client_init();
    //设置服务器地址
    smtp_set_server_addr(SMTP_SERVER_ADDR, ADDRESS_TYPE_DOMAIN, SMTP_SERVER_PORT);
    //设置服务器认证信息
    smtp_set_auth(SMTP_USERNAME, SMTP_PASSWORD);
    //添加收件人1
    smtp_add_receiver("66666@sharklasers.com");

    while (1)
    {
        if (send_enable)
        {
            smtp_add_attachment("/a.txt", "a.txt");
            smtp_add_attachment("/b.txt", "b.txt");
            //发送邮件
            LOG_D("start to send mail");
            if (smtp_send_mail(SMTP_SUBJECT, content) == 0)
            {
                //发送成功
                LOG_I("send mail success!");
            }
            else
            {
                //发送失败
                LOG_E("send mail fail!");
            }
            //清除附件
            smtp_clear_attachments();
            //防止频繁发送
            rt_thread_mdelay(30000);
            send_enable = 0;
        }
        else
        {
            rt_thread_mdelay(500);
        }
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

int smtp_test(uint8_t argc, char *argv[])
{
    send_enable = 1;
    return 0;
}
MSH_CMD_EXPORT(smtp_test, smtp test);
```

## 联系方式&感谢

- 维护: WKJay
- 主页：https://github.com/WKJay/SMTP_CLIENT
- email: 1931048074@qq.com
- 若在使用过程中有任何问题，请与作者取得联系。同时欢迎大家参与到该软件包的开发与维护中来，共同创建一个更加完善、稳定的软件包。

