/*************************************************
 Copyright (c) 2019
 All rights reserved.
 File name:     smtp_client.c
 Description:   smtp源文件
 History:
 1. Version:    
    Date:       2019-10-10
    Author:     wangjunjie
    Modify:     
*************************************************/

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <dfs_posix.h>

#include "smtp_client_private.h"
#include "smtp_client_data.h"
#include "smtp_client.h"
#include "netdb.h"

smtp_session_t smtp_session;

/**
 * Name:    smtp_client_init
 * Brief:   初始化smtp客户端
 * Input:   None
 * Output:  None
 */
void smtp_client_init(void)
{
    memset(&smtp_session, 0, sizeof(smtp_session_t));
}

/**
 * Name:    smtp_close_connection
 * Brief:   smtp关闭连接，释放资源
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_close_connection(void)
{
    int server_port_num = atoi(smtp_session.server_port);
    if (server_port_num == 25)
    {
        return closesocket(smtp_session.conn_fd);
    }
#ifdef SMTP_CLIENT_USING_TLS
    else if (server_port_num == 465 || server_port_num == 587)
    {
        return smtp_mbedtls_close_connection();
    }
#endif
    else
    {
        return -1;
    }
}

/**
 * Name:    smtp_set_server_addr
 * Brief:   设置邮箱服务器域名和端口
 *          地址最大长度由 SMTP_MAX_ADDR_LEN 定义
 * Input:
 *  @server_addr: 服务器地址
 *  @addr_type:   地址类型  
 *                ADDR_TYPE_DOMAIN  域名类型
 *                ADDR_TYPE_IP      IP地址类型
 *  @port:        服务器端口
 * Output:        0:设置成功，-1,：设置失败  
 */
int smtp_set_server_addr(const char *server_addr, uint8_t addr_type, const char *port)
{
    uint16_t addr_len = 0;
    if (server_addr != NULL)
    {
        addr_len = strlen(server_addr);
    }
    else
    {
        SMTP_LOG("[smtp]: X  server addr is null!\r\n");
        return -1;
    }

    if (addr_type == ADDRESS_TYPE_DOMAIN)
    {
        smtp_session.server_domain = server_addr;
    }
    else
    {
        if (addr_len > 15)
        {
            SMTP_LOG("[smtp]: X  server addr type error!\r\n");
            return -1;
        }
        else
        {
            smtp_session.server_ip = server_addr;
        }
    }

    if (strlen(port) <= 0)
    {
        SMTP_LOG("[smtp]: X  server port is null!\r\n");
        return -1;
    }
    else
    {
        smtp_session.server_port = port;
    }
    return 0;
}

/**
 * Name:    smtp_set_auth
 * Brief:   设置连接smtp服务的用户名和密码
 * Input:
 *  @username:  用户名
 *  @password:  密码
 * Output:  设置成功：0，设置失败：-1
 */
int smtp_set_auth(const char *username, const char *password)
{
    uint32_t username_len = strlen(username);
    uint32_t password_len = strlen(password);

    if (!(username_len && password_len))
    {
        SMTP_LOG("[smtp]: X  username or password invalid!\r\n");
        return -1;
    }

    if (smtp_base64_encode(smtp_session.username, SMTP_MAX_AUTH_LEN * 2, username, username_len) == 0)
    {
        SMTP_LOG("[smtp]: X  username encode error!\r\n");
        return -1;
    }

    if (smtp_base64_encode(smtp_session.password, SMTP_MAX_AUTH_LEN * 2, password, password_len) == 0)
    {
        SMTP_LOG("[smtp]: X  password encode error!\r\n");
        return -1;
    }

    return 0;
}

/**
 * Name:    smtp_connect_server_by_hostname
 * Brief:   通过域名连接smtp服务器
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_connect_server_by_hostname(void)
{
    int result = -1;
    char buf[3];
    struct addrinfo hints, *addr_list, *cur;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(smtp_session.server_domain, smtp_session.server_port, &hints, &addr_list) != 0)
    {
        SMTP_LOG("[smtp]: X  unknow server domain!\r\n");
        return -1;
    }

    for (cur = addr_list; cur != NULL; cur = cur->ai_next)
    {
        smtp_session.conn_fd = (int)socket(cur->ai_family, cur->ai_socktype,
                                           cur->ai_protocol);
        if (smtp_session.conn_fd < 0)
        {
            result = -1;
            continue;
        }

        if (connect(smtp_session.conn_fd, cur->ai_addr, (uint32_t)cur->ai_addrlen) == 0)
        {
            if (read(smtp_session.conn_fd, buf, 3) < 3)
            {
                SMTP_LOG("[smtp]: X  smtp server connect fail\r\n");
                smtp_close_connection();
                result = -1;
                break;
            }
            else
            {
                if (memcmp(buf, "220", 3) == 0)
                {
                    SMTP_LOG("\r\n[smtp]: O  smtp server connect success!\r\n");
                    SMTP_LOG("[smtp]: O  smtp server domain -> %s!\r\n", smtp_session.server_domain);
                    result = 0;
                    break;
                }
                else
                {
                    SMTP_LOG("[smtp]: X  smtp connection response check fail\r\n");
                    smtp_close_connection();
                    result = -1;
                    break;
                }
            }
        }
        SMTP_LOG("[smtp]: X  smtp server connect fail\r\n");
        smtp_close_connection();
        result = -1;
    }

    freeaddrinfo(addr_list);
    return result;
}

/**
 * Name:    smtp_connect_server_by_ip
 * Brief:   通过IP连接smtp服务器
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_connect_server_by_ip(void)
{
    int result = -1;

    SMTP_LOG("[smtp]: X  current version don't support ip connect,please use server domain!\r\n");

    return result;
}

/**
 * Name:    smtp_flush
 * Brief:   清空smtp数据读取区缓存
 * Input:   None
 * Output:  缓存中的数据个数，失败返回-1
 */
static int smtp_flush(void)
{
    int result = -1;
    int server_port = atoi(smtp_session.server_port);
    char buf[SMTP_RESPONSE_MAX_LEN];

    while (1)
    {
        if (server_port == 25)
        {
            result = read(smtp_session.conn_fd, buf, SMTP_RESPONSE_MAX_LEN);
        }
#ifdef SMTP_CLIENT_USING_TLS
        else if (server_port == 465)
        {
            result = smtp_mbedtls_client_read(smtp_session.tls_session, buf, SMTP_RESPONSE_MAX_LEN);
        }
        else if (server_port == 587)
        {
            if (smtp_session.state == SMTP_FINISH_START_TLS)
            {
                return 0;
            }
            else if (smtp_session.state < SMTP_AUTH_LOGIN)
            {
                result = read(smtp_session.conn_fd, buf, SMTP_RESPONSE_MAX_LEN);
            }
            else
            {
                result = smtp_mbedtls_client_read(smtp_session.tls_session, buf, SMTP_RESPONSE_MAX_LEN);
            }
        }
#endif
        else
        {
            SMTP_LOG("[smtp]: X  smtp flush port invalid \r\n");
            return -1;
        }

        if (result <= 0)
        {
            SMTP_LOG("[smtp]: X  smtp net connection flush fail\r\n");
            return -1;
        }
        return result;
    }
}

/**
 * Name:    smtp_write
 * Brief:   根据不同的状态调用对应的write
 * Input:
 *  @buf:   要写入的数据
 * Output:  成功写入的个数，错误返回-1
 */
static int smtp_write(char *buf)
{
    int server_port_num = atoi(smtp_session.server_port);
    if (server_port_num == 25)
    {
        return write(smtp_session.conn_fd, buf, strlen(buf));
    }
#ifdef SMTP_CLIENT_USING_TLS
    else if (server_port_num == 465)
    {
        return smtp_mbedtls_client_write(smtp_session.tls_session, buf);
    }
    else if (server_port_num == 587)
    {
        if (smtp_session.state < SMTP_FINISH_START_TLS)
        {
            return write(smtp_session.conn_fd, buf, strlen(buf));
        }
        else
        {
            return smtp_mbedtls_client_write(smtp_session.tls_session, buf);
        }
    }
#endif
    else
    {
        return -1;
    }
}

/**
 * Name:    smtp_read
 * Brief:   根据不同的状态调用对应的read
 * Input:
 *  @buf:   读取数据的存储区
 *  @nbyte: 准备读取数据的长度
 * Output:  成功读取的个数，错误返回-1
 */
static int smtp_read(void *buf, size_t nbyte)
{
    int server_port_num = atoi(smtp_session.server_port);
    if (server_port_num == 25)
    {
        return read(smtp_session.conn_fd, buf, nbyte);
    }
#ifdef SMTP_CLIENT_USING_TLS
    else if (server_port_num == 465)
    {
        return smtp_mbedtls_client_read(smtp_session.tls_session, buf, nbyte);
    }
    else if (server_port_num == 587)
    {
        if (smtp_session.state < SMTP_FINISH_START_TLS)
        {
            return read(smtp_session.conn_fd, buf, nbyte);
        }
        else
        {
            return smtp_mbedtls_client_read(smtp_session.tls_session, buf, nbyte);
        }
    }
#endif
    else
    {
        return -1;
    }
}

/**
 * Name:    smtp_connect_server
 * Brief:   smtp连接服务器
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_connect_server(void)
{
    int server_port_num = atoi(smtp_session.server_port);
    if (server_port_num == 25)
    {
        if (smtp_session.server_ip)
        {
            return smtp_connect_server_by_ip();
        }
        else if (smtp_session.server_domain)
        {
            return smtp_connect_server_by_hostname();
        }
        else
        {
            SMTP_LOG("[smtp]: X  cannot find ip and domain\r\n");
            return -1;
        }
    }
#ifdef SMTP_CLIENT_USING_TLS
    else if (server_port_num == 465)
    {
        return smtp_connect_server_by_tls();
    }
    else if (server_port_num == 587)
    {
        return smtp_connect_server_by_starttls();
    }
#endif
    else
    {
        SMTP_LOG("[smtp]: X  invalid port number!\r\n");
        return -1;
    }
}

/**
 * Name:    smtp_send_data_with_response_check
 * Brief:   smtp数据发送并校验响应
 * Input:   
 *  @buf:   待发送的数据
 *  @response_code: 正确响应码
 * Output:  成功0，失败-1
 */
static int smtp_send_data_with_response_check(char *buf, char *response_code)
{
    char response_code_buf[3];
    memset(response_code_buf, 0, 3);

    if (smtp_session.conn_fd == 0
#ifdef SMTP_CLIENT_USING_TLS
        && smtp_session.tls_session == 0)
#else
    )
#endif
    {
        SMTP_LOG("[smtp]: X  cannot find net fd\r\n");
        return -1;
    }
    else
    {
        smtp_flush();
        if (smtp_write(buf) != strlen(buf))
        {
            SMTP_LOG("[smtp]: X  smtp send fail\r\n");
            smtp_close_connection();
            return -1;
        }
        else
        {
            if (smtp_read(response_code_buf, 3) < 3)
            {
                SMTP_LOG("[smtp]: X  smtp read  response fail\r\n");
                smtp_close_connection();
                return -1;
            }
            if (memcmp(response_code, response_code_buf, 3) != 0)
            {
                SMTP_LOG("[smtp]: X  smtp check  response fail\r\n");
                smtp_close_connection();
                return -1;
            }
            else
            {
                return 0;
            }
        }
    }
}

/**
 * Name:    smtp_handshake
 * Brief:   smtp握手认证
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_handshake(void)
{
    int result = -1;
    result = smtp_send_data_with_response_check(SMTP_CMD_EHLO, "250");
    if (result != 0)
    {
        SMTP_LOG("[smtp]: X  smtp helo fail\r\n");
        return -1;
    }

#ifdef SMTP_CLIENT_USING_TLS
    //STARTTLS
    if (atoi(smtp_session.server_port) == 587)
    {
        smtp_session.state = SMTP_START_TLS;
        if (smtp_send_data_with_response_check(SMTP_CMD_STARTTLS, "220") != 0)
        {
            SMTP_LOG("[smtp]: X  smtp start tls fail\r\n");
            smtp_close_connection();
            return -1;
        }

        smtp_flush();

        if (smtp_mbedtls_starttls(smtp_session.tls_session) != 0)
        {
            SMTP_LOG("[smtp]: X  smtp start tls handshake fail\r\n");
            return -1;
        }
        return 0;
    }
#endif
    return result;
}

/**
 * Name:    smtp_auth_login
 * Brief:   smtp用户登录
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_auth_login(void)
{
    char auth_info_buf[SMTP_MAX_AUTH_LEN * 2 + 2];
    memset(auth_info_buf, 0, SMTP_MAX_AUTH_LEN * 2 + 2);
#ifdef SMTP_CLIENT_USING_TLS
    if (atoi(smtp_session.server_port) == 587)
    {
        smtp_session.state = SMTP_FINISH_START_TLS;
    }
#endif
    if (smtp_send_data_with_response_check(SMTP_CMD_AUTHLOGIN, "334") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp auth login fail\r\n");
        smtp_close_connection();
        return -1;
    }
#ifdef SMTP_CLIENT_USING_TLS
    if (atoi(smtp_session.server_port) == 587)
    {
        smtp_session.state = SMTP_AUTH_LOGIN;
    }
#endif
    //发送用户名信息
    sprintf(auth_info_buf, "%s\r\n", smtp_session.username);
    if (smtp_send_data_with_response_check(auth_info_buf, "334") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp send username fail\r\n");
        smtp_close_connection();
        return -1;
    }
    //发送密码信息
    sprintf(auth_info_buf, "%s\r\n", smtp_session.password);
    if (smtp_send_data_with_response_check(auth_info_buf, "235") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp password invalid\r\n");
        smtp_close_connection();
        return -1;
    }
    return 0;
}

/**
 * Name:    smtp_set_sender_receiver
 * Brief:   smtp设置邮箱的发件人与收件人
 * Input:   None
 * Output:  发送成功0，发送失败-1
 */
static int smtp_set_sender_receiver(void)
{
    uint16_t mail_buf_len = SMTP_MAX_ADDR_LEN + strlen(SMTP_CMD_MAIL_HEAD) + strlen(SMTP_CMD_MAIL_END);
    uint16_t rcpt_buf_len = SMTP_MAX_ADDR_LEN + strlen(SMTP_CMD_RCPT_HEAD) + strlen(SMTP_CMD_RCPT_END);
    //使用较大的长度
    uint16_t buf_len = (mail_buf_len > rcpt_buf_len) ? mail_buf_len : rcpt_buf_len;

    char addr_info_buf[buf_len];
    memset(addr_info_buf, 0, buf_len);

    sprintf(addr_info_buf, "%s%s%s", SMTP_CMD_MAIL_HEAD, smtp_session.address_from, SMTP_CMD_MAIL_END);
    if (smtp_send_data_with_response_check(addr_info_buf, "250") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp set mail from fail\r\n");
        smtp_close_connection();
        return -1;
    }

    sprintf(addr_info_buf, "%s%s%s", SMTP_CMD_RCPT_HEAD, smtp_session.address_to, SMTP_CMD_RCPT_END);
    if (smtp_send_data_with_response_check(addr_info_buf, "250") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp set rcpt to fail\r\n");
        smtp_close_connection();
        return -1;
    }
    return 0;
}

/**
 * Name:    smtp_send_content
 * Brief:   smtp发送邮件内容
 * Input:   None
 * Output:  发送成功0，发送失败-1
 */
static int smtp_send_content(void)
{
    char content_buf[SMTP_SEND_DATA_HEAD_MAX_LENGTH + SMTP_SEND_DATA_MAX_LEN];
    memset(content_buf, 0, SMTP_SEND_DATA_HEAD_MAX_LENGTH + SMTP_SEND_DATA_MAX_LEN);

    if (smtp_send_data_with_response_check(SMTP_CMD_DATA, "354") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp send data cmd fail\r\n");
        smtp_close_connection();
        return -1;
    }
    //拼接内容
    sprintf(content_buf, "FROM: <%s>\r\nTO: <%s>\r\nSUBJECT:%s\r\n\r\n%s\r\n.\r\n",
            smtp_session.address_from, smtp_session.address_to, smtp_session.subject, smtp_session.body);

    if (smtp_send_data_with_response_check(content_buf, "250") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp send data content fail\r\n");
        smtp_close_connection();
        return -1;
    }

    return 0;
}

/**
 * Name:    smtp_quit
 * Brief:   smtp 结束一次完整的通信
 * Input:   None
 * Output:  成功0，失败-1
 */
static int smtp_quit(void)
{
    if (smtp_send_data_with_response_check(SMTP_CMD_QUIT, "221") != 0)
    {
        SMTP_LOG("[smtp]: X  smtp quit fail\r\n");
        smtp_close_connection();
        return -1;
    }
    SMTP_LOG("[smtp]: O  smtp mail send sussess!\r\n");
    //关闭连接
    smtp_close_connection();
    SMTP_LOG("[smtp]: O  close smtp connection!\r\n");
    return 0;
}

/**
 * Name:    smtp_send
 * Brief:   真实的发送函数
 * Input:   
 *  @port_num:  发送邮件的端口号字符串
 * Output:  发送成功0，发送失败-1
 */
static int smtp_send(void)
{
    //连接服务器
    smtp_session.state = SMTP_NULL;
    if (smtp_connect_server() != 0)
    {
        return -1;
    }
    //握手确认
    smtp_session.state = SMTP_HELO;
    if (smtp_handshake() != 0)
    {
        return -1;
    }
    //用户认证
    smtp_session.state = SMTP_AUTH_LOGIN;
    if (smtp_auth_login() != 0)
    {
        return -1;
    }
    //设置发件人与收件人
    smtp_session.state = SMTP_MAIL;
    if (smtp_set_sender_receiver() != 0)
    {
        return -1;
    }
    //发送数据
    smtp_session.state = SMTP_DATA;
    if (smtp_send_content() != 0)
    {
        return -1;
    }
    //结束
    smtp_session.state = SMTP_QUIT;
    if (smtp_quit() != 0)
    {
        return -1;
    }
    return 0;
}

/**
 * Name:    smtp_send_mail
 * Brief:   smtp邮件发送
 * Input:
 *  @from:     发送者邮箱
 *  @to:       接受者邮箱
 *  @subject:  主题
 *  @body:     内容
 * Output:  成功0，失败-1
 */
int smtp_send_mail(char *from, char *to, char *subject, char *body)
{
    if (strlen(from) > SMTP_MAX_ADDR_LEN)
    {
        SMTP_LOG("[smtp]: X  sender address is too long!\r\n");
        return -1;
    }
    else
    {
        smtp_session.address_from = from;
    }

    if (strlen(to) > SMTP_MAX_ADDR_LEN)
    {
        SMTP_LOG("[smtp]: X  receiver address is too long!\r\n");
        return -1;
    }
    else
    {
        smtp_session.address_to = to;
    }

    if (subject == NULL)
    {
        SMTP_LOG("[smtp]: X subject is null!\r\n");
        return -1;
    }
    else
    {
        smtp_session.subject = subject;
    }

    if (body == NULL)
    {
        SMTP_LOG("[smtp]: X body is null!\r\n");
        return -1;
    }
    else
    {
        smtp_session.body = body;
    }

    //调用真实的发送函数
    return smtp_send();
}
