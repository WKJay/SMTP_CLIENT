# SMTP_CLIENT V1.0.0

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

```

- **Version：** 配置软件版本
- **use 465/587 port(encrypted port):** 使用加密端口，选中后会将 **mbedtls** 软件包加入编译，同时开启 465和587 两个加密端口的支持。
- **enable debug log information：** 使能调试打印信息
- **smtp client example：** 加入示例文件

**注意：加入示例文件后不能直接下载使用，默认示例中缺少SMTP的个人参数，需要用户补全自己的用户名密码及接收方邮箱等信息！**

#### 注意事项

 - 开启加密功能后会占用比较大的RAM空间，请根据自己使用的硬件平台决定是否选用加密。并且适当调大调用发送功能的线程的堆栈大小。（推荐大于4096）
 - 有些邮件服务器不支持某个加密端口或者默认关闭，使用者需要确认自己选用的邮件服务器所支持的端口，并且确认已经打开邮件服务器的SMTP功能。
 - 若用户在使用的过程中出现加密有关的错误，请参照 RT-Thread **mbedtls** 软件包的说明文档。

 ### 使用说明

 #### 使用步骤

 1. 调用 `smtp_client_init` 函数初始化 smtp_client 客户端
 2. 调用 `smtp_set_server_addr` 函数设置服务器的地址及端口
 3. 调用 `smtp_set_auth` 函数设置服务器认证信息
 4. 调用 `smtp_send_mail` 函数发送邮件

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

##### 4、发送邮件

```C

int smtp_send_mail(char *from, char *to, char *subject, char *body);

```

|参数|说明|
|---|---|
|from|发送者邮箱地址|
|to|接收者邮箱地址|
|subject|主题|
|body|内容|

|返回值|说明|
|----|----|
|0|发送成功|
|-1|发送失败|

该函数为邮件发送函数，在用户设置好服务器的连接参数后，可以直接调用该函数进行邮件的发送。需要注意的是，发送者邮箱地址必须和登录用户名相同。

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

## 联系方式&感谢

- 维护: WKJay
- 主页：https://github.com/WKJay/SMTP_CLIENT
- email: 1931048074@qq.com
- 若在使用过程中有任何问题，请与作者取得联系。同时欢迎大家参与到该软件包的开发与维护中来，共同创建一个更加完善、稳定的软件包。

