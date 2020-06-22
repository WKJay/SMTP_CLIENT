/*************************************************
 Copyright (c) 2019
 All rights reserved.
 File name:     smtp_client.c
 Description:   smtp源文件
 History:
 1. Version:    V1.0.0
    Date:       2019-10-10
    Author:     WKJay
    Modify:     新建

 2. Version:    V1.0.1
    Date:       2019-10-28
    Author:     WKJay
    Modify:     增加多个收件人功能
    
 3. Version:    V1.0.2
    Date:       2020-06-22
    Author:     WKJay
    Modify:     增加附件功能
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

#ifdef SMTP_CLIENT_USING_ATTACHMENT
/**
 * Name:    smtp_add_attachment
 * Brief:   添加附件
 * Input:   
 *  @file_path: 文件路径
 *  @file_name: 文件名
 * Output:  成功:0 , 失败:-1
 */
int smtp_add_attachment(char *file_path, char *file_name)
{
    FILE *fp =  NULL;
    if (strlen(file_path) > SMTP_MAX_FILE_PATH_LEN)
    {
        LOG_E("attachment's file path too large");
        return -1;
    }

    if (strlen(file_name) > SMTP_ATTACHMENT_MAX_NAME_LEN)
    {
        LOG_E("attachment's file name too large");
        return -1;
    }

    fp = fopen(file_path, "r");
    if (fp == NULL)
    {
        LOG_E("cannot open file %s", file_path);
        return -1;
    }
    fclose(fp);

    if (!smtp_session.attachments)
    {
        smtp_session.attachments = rt_malloc(sizeof(smtp_attachments_t));
        if (smtp_session.attachments)
        {
            rt_memset(smtp_session.attachments, 0, sizeof(smtp_attachments_t));
            rt_memcpy(smtp_session.attachments->file_path, file_path, strlen(file_path));
            rt_memcpy(smtp_session.attachments->file_name, file_name, strlen(file_name));
        }
        else
        {
            LOG_E("attachment memory allocate failed");
            return -1;
        }
    }
    else
    {
        smtp_attachments_t *cur_att = smtp_session.attachments;
        while (cur_att->next)
        {
            cur_att = cur_att->next;
        }
        cur_att->next = rt_malloc(sizeof(smtp_attachments_t));
        if (cur_att->next)
        {
            rt_memset(cur_att->next, 0, sizeof(smtp_attachments_t));
            rt_memcpy(cur_att->next->file_path, file_path, strlen(file_path));
            rt_memcpy(cur_att->next->file_name, file_name, strlen(file_name));
        }
        else
        {
            LOG_E("attachment memory allocate failed");
            return -1;
        }
    }

    return 0;
}

//清除所有附件
void smtp_clear_attachments(void)
{
    smtp_attachments_t *cur_attr, *next_attr;
    for (cur_attr = smtp_session.attachments; cur_attr; cur_attr = next_attr)
    {
        next_attr = cur_attr->next;
        LOG_D("delete attachment:%s", cur_attr->file_path);
        rt_free(cur_attr);
    }
    smtp_session.attachments = NULL;
}
#endif

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
        LOG_E("server addr is null!");
        return -1;
    }

    if (addr_type == ADDRESS_TYPE_DOMAIN)
    {
        if (smtp_session.server_domain)
        {
            rt_free(smtp_session.server_domain);
        }
        smtp_session.server_domain = rt_strdup(server_addr);
    }
    else
    {
        if (addr_len > 15)
        {
            LOG_E("server addr type error!");
            return -1;
        }
        else
        {
            if (smtp_session.server_ip)
            {
                rt_free(smtp_session.server_ip);
            }
            smtp_session.server_ip = rt_strdup(server_addr);
        }
    }

    if (strlen(port) <= 0)
    {
        LOG_E("server port is null!");
        return -1;
    }
    else
    {
        if (smtp_session.server_port)
        {
            rt_free(smtp_session.server_port);
        }
        smtp_session.server_port = rt_strdup(port);
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
        LOG_E("username or password invalid!");
        return -1;
    }

    //设置SMTP MAIL FROM属性，该属性必须与用户名一致
    if (username_len > SMTP_MAX_ADDR_LEN)
    {
        LOG_E("sender address id too long");
        return -1;
    }
    memset(smtp_session.address_from, 0, SMTP_MAX_ADDR_LEN);
    memset(smtp_session.username, 0, sizeof(smtp_session.username));
    memset(smtp_session.password, 0, sizeof(smtp_session.password));

    memcpy(smtp_session.address_from, username, username_len);

    if (smtp_base64_encode(smtp_session.username, SMTP_MAX_AUTH_LEN * 2, username, username_len) == 0)
    {
        LOG_E("username encode error!");
        return -1;
    }

    if (smtp_base64_encode(smtp_session.password, SMTP_MAX_AUTH_LEN * 2, password, password_len) == 0)
    {
        LOG_E("password encode error!");
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
        LOG_E("unknow server domain!");
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
                LOG_E("smtp server connect fail");
                smtp_close_connection();
                result = -1;
                break;
            }
            else
            {
                if (memcmp(buf, "220", 3) == 0)
                {
                    LOG_I("smtp server connect success!");
                    LOG_I("smtp server domain -> %s!", smtp_session.server_domain);
                    result = 0;
                    break;
                }
                else
                {
                    LOG_E("smtp connection response check fail");
                    smtp_close_connection();
                    result = -1;
                    break;
                }
            }
        }
        LOG_E("smtp server connect fail");
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

    LOG_E("current version don't support ip connect,please use server domain!");

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
            LOG_E("smtp flush port invalid");
            return -1;
        }

        if (result <= 0)
        {
            LOG_E("smtp net connection flush fail");
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
 *  @len:   写入长度
 * Output:  成功写入的个数，错误返回-1
 */
static int smtp_write(uint8_t *buf, uint32_t len)
{
    int server_port_num = atoi(smtp_session.server_port);
    if (server_port_num == 25)
    {
        return write(smtp_session.conn_fd, buf, len);
    }
#ifdef SMTP_CLIENT_USING_TLS
    else if (server_port_num == 465)
    {
        return smtp_mbedtls_client_write(smtp_session.tls_session, buf, len);
    }
    else if (server_port_num == 587)
    {
        if (smtp_session.state < SMTP_FINISH_START_TLS)
        {
            return write(smtp_session.conn_fd, buf, len);
        }
        else
        {
            return smtp_mbedtls_client_write(smtp_session.tls_session, buf, len);
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
            LOG_E("cannot find ip and domain");
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
        LOG_E("invalid port number!");
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
        LOG_E("cannot find net fd");
        return -1;
    }
    else
    {
        smtp_flush();
        if (smtp_write((uint8_t *)buf, strlen(buf)) != strlen(buf))
        {
            LOG_E("smtp send fail");
            smtp_close_connection();
            return -1;
        }
        else
        {
            if (smtp_read(response_code_buf, 3) < 3)
            {
                LOG_E("smtp read  response fail");
                smtp_close_connection();
                return -1;
            }
            if (memcmp(response_code, response_code_buf, 3) != 0)
            {
                LOG_E("smtp check  response fail");
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
        LOG_E("smtp helo fail");
        return -1;
    }

#ifdef SMTP_CLIENT_USING_TLS
    //STARTTLS
    if (atoi(smtp_session.server_port) == 587)
    {
        smtp_session.state = SMTP_START_TLS;
        if (smtp_send_data_with_response_check(SMTP_CMD_STARTTLS, "220") != 0)
        {
            LOG_E("smtp start tls fail");
            smtp_close_connection();
            return -1;
        }

        smtp_flush();

        if (smtp_mbedtls_starttls(smtp_session.tls_session) != 0)
        {
            LOG_E("smtp start tls handshake fail");
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
        LOG_E("smtp auth login fail");
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
        LOG_E("smtp send username fail");
        smtp_close_connection();
        return -1;
    }
    //发送密码信息
    sprintf(auth_info_buf, "%s\r\n", smtp_session.password);
    if (smtp_send_data_with_response_check(auth_info_buf, "235") != 0)
    {
        LOG_E("smtp password invalid");
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
    smtp_address_to_t *smtp_address_to_temp = smtp_session.address_to;

    char addr_info_buf[buf_len];
    memset(addr_info_buf, 0, buf_len);

    sprintf(addr_info_buf, "%s%s%s", SMTP_CMD_MAIL_HEAD, smtp_session.address_from, SMTP_CMD_MAIL_END);
    if (smtp_send_data_with_response_check(addr_info_buf, "250") != 0)
    {
        LOG_E("smtp set mail from fail");
        smtp_close_connection();
        return -1;
    }

    while (smtp_address_to_temp)
    {
        sprintf(addr_info_buf, "%s%s%s", SMTP_CMD_RCPT_HEAD, smtp_address_to_temp->addr, SMTP_CMD_RCPT_END);
        if (smtp_send_data_with_response_check(addr_info_buf, "250") != 0)
        {
            LOG_E("smtp set rcpt to fail");
            smtp_close_connection();
            return -1;
        }
        smtp_address_to_temp = smtp_address_to_temp->next;
    }

    return 0;
}

/**
 * Name:    smtp_send_content
 * Brief:   smtp发送附件
 * Input:   None
 * Output:  None
 */
static void smtp_send_attachment(void)
{
    uint8_t attachment_buf[SMTP_SEND_DATA_MAX_LEN];
    smtp_attachments_t *cur_attr = smtp_session.attachments;
    while (cur_attr)
    {
        FILE *fp = fopen(cur_attr->file_path, "r");
        if (fp)
        {
            uint32_t read_size = 0;
            //发送附件头
            rt_memset(attachment_buf, 0, sizeof(attachment_buf));
            sprintf((char *)attachment_buf,
                    "--" SMTP_MAIL_BOUNDARY "\r\n"
                    "Content-Type: text/plain; name=\"%s\"\r\n"
                    "Content-Transfer-Encoding: binary\r\n"
                    "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n",
                    cur_attr->file_name, cur_attr->file_name);
            smtp_write(attachment_buf, strlen((char *)attachment_buf));

            //发送附件数据
            rt_memset(attachment_buf, 0, sizeof(attachment_buf));
            read_size = fread(attachment_buf, 1, sizeof(attachment_buf), fp);
            while (read_size == sizeof(attachment_buf))
            {
                smtp_write(attachment_buf, read_size);
                read_size = fread(attachment_buf, 1, sizeof(attachment_buf), fp);
                rt_thread_mdelay(1);
            }
            smtp_write(attachment_buf, read_size);
            smtp_write((uint8_t *)"\r\n\r\n", strlen("\r\n\r\n"));
            fclose(fp);
        }
        else
        {
            LOG_E("add attachment %s failed,path: %s", cur_attr->file_name, cur_attr->file_path);
        }
        cur_attr = cur_attr->next;
    }
    smtp_write((uint8_t *)("--" SMTP_MAIL_BOUNDARY "--\r\n"), strlen("--" SMTP_MAIL_BOUNDARY "--\r\n"));
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
        LOG_E("smtp send data cmd fail");
        smtp_close_connection();
        return -1;
    }
    //拼接内容

#ifdef SMTP_CLIENT_USING_ATTACHMENT
    if (smtp_session.attachments)
    {
        sprintf(content_buf,
                "FROM:<%s>\r\n"
                "TO:<%s>\r\n"
                "SUBJECT:%s\r\n"
                "Content-Type: multipart/mixed;"
                "boundary=\"smtp_client_boundary\"\r\n\r\n"
                "--" SMTP_MAIL_BOUNDARY "\r\n"
                "Content-Type: text/plain; charset=\"utf-8\"\r\n"
                "Content-Transfer-Encoding: 7bit\r\n\r\n"
                "%s\r\n\r\n",
                smtp_session.address_from, smtp_session.address_to->addr, smtp_session.subject, smtp_session.body);
    }
    else
    {
        sprintf(content_buf,
                "FROM: <%s>\r\n"
                "TO: <%s>\r\n"
                "SUBJECT:%s\r\n\r\n"
                "%s\r\n\r\n",
                smtp_session.address_from, smtp_session.address_to->addr, smtp_session.subject, smtp_session.body);
    }

#else
    sprintf(content_buf,
            "FROM: <%s>\r\n"
            "TO: <%s>\r\n"
            "SUBJECT:%s\r\n\r\n"
            "%s\r\n\r\n",
            smtp_session.address_from, smtp_session.address_to->addr, smtp_session.subject, smtp_session.body);
#endif

    smtp_write((uint8_t *)content_buf, strlen(content_buf));

#ifdef SMTP_CLIENT_USING_ATTACHMENT
    smtp_send_attachment();
#endif
    if (smtp_send_data_with_response_check(SMTP_CMD_BODY_FINISHED, "250") != 0)
    {
        LOG_E("smtp send data content fail");
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
        LOG_E("smtp quit fail");
        smtp_close_connection();
        return -1;
    }
    LOG_I("smtp mail send sussess!");
    //关闭连接
    smtp_close_connection();
    LOG_I("close smtp connection!");
    return 0;
}

/**
 * Name:    smtp_send
 * Brief:   真实的发送函数
 * Input:   
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
 *  @subject:  主题
 *  @body:     内容
 * Output:  成功0，失败-1
 */
int smtp_send_mail(char *subject, char *body)
{
    if (subject == NULL)
    {
        LOG_E("subject is null!");
        return -1;
    }
    else
    {
        smtp_session.subject = subject;
    }

    if (body == NULL)
    {
        LOG_E("body is null!");
        return -1;
    }
    else
    {
        smtp_session.body = body;
    }

    //调用真实的发送函数
    return smtp_send();
}

/**
 * Name:    smtp_add_receiver
 * Brief:   增加收件人
 * Input:
 *  @receiver_addr: 收件人地址
 * Output:  成功返回0，失败返回-1
 */
int smtp_add_receiver(char *receiver_addr)
{
    smtp_address_to_t *smtp_address_to_temp = RT_NULL;
    //用于释放问题节点
    smtp_address_to_t *smtp_address_to_free_temp = RT_NULL;

    if (receiver_addr == RT_NULL)
    {
        LOG_E("receiver addr is null");
        return -1;
    }

    if (smtp_session.address_to == RT_NULL)
    {
        smtp_session.address_to = rt_malloc(sizeof(smtp_address_to_t));
        if (smtp_session.address_to == RT_NULL)
        {
            LOG_E("smtp receiver address node allocate fail");
            return -1;
        }
        memset(smtp_session.address_to, 0, sizeof(smtp_address_to_t));
        smtp_address_to_temp = smtp_session.address_to;
    }
    else
    {
        smtp_address_to_temp = smtp_session.address_to;
        while (smtp_address_to_temp->next != RT_NULL)
        {
            smtp_address_to_temp = smtp_address_to_temp->next;
        }
        smtp_address_to_temp->next = rt_malloc(sizeof(smtp_address_to_t));
        smtp_address_to_temp = smtp_address_to_temp->next;
        if (smtp_address_to_temp == RT_NULL)
        {
            LOG_E("smtp receiver address node allocate fail");
            return -1;
        }
        memset(smtp_address_to_temp, 0, sizeof(smtp_address_to_t));
    }

    //新建一个收件人地址存储区
    smtp_address_to_temp->addr = rt_malloc(strlen(receiver_addr) + 1);
    if (smtp_address_to_temp->addr == RT_NULL)
    {
        LOG_E("smtp receiver address string allocate fail");
        LOG_W("start to free address node");
        //找出需要释放节点的上一个节点，并将其next指向空
        smtp_address_to_free_temp = smtp_session.address_to;
        while (smtp_address_to_free_temp->next != smtp_address_to_temp)
        {
            smtp_address_to_free_temp = smtp_address_to_free_temp->next;
        }
        smtp_address_to_free_temp->next = RT_NULL;
        //释放问题节点
        rt_free(smtp_address_to_temp);
        LOG_I("address node free success!");

        return -1;
    }
    memset(smtp_address_to_temp->addr, 0, strlen(receiver_addr) + 1);
    memcpy(smtp_address_to_temp->addr, receiver_addr, strlen(receiver_addr));
    return 0;
}

/**
 * Name:    smtp_clear_receiver
 * Brief:   删除所有收件人
 * Input:   None
 * Output:  None
 */
void smtp_clear_receiver(void)
{
    //上一个节点指针
    smtp_address_to_t *cur_receiver, *next_receiver;

    for (cur_receiver = smtp_session.address_to; cur_receiver; cur_receiver = next_receiver)
    {
        next_receiver = cur_receiver->next;
        LOG_D("delete receiver:%s", cur_receiver->addr);
        rt_free(cur_receiver->addr);
        rt_free(cur_receiver);
    }
    smtp_session.address_to = NULL;
}

/**
 * Name:    smtp_delete_receiver
 * Brief:   删除某个收件人
 * Input:
 *  @receiver_addr: 收件人地址
 * Output:  成功返回0，失败返回-1
 */
int smtp_delete_receiver(char *receiver_addr)
{
    //上一个节点指针
    smtp_address_to_t *smtp_address_to_last = RT_NULL;
    //待删除节点指针
    smtp_address_to_t *smtp_address_to_delete = RT_NULL;

    //将待删除指针指向收件人链表头结点
    smtp_address_to_delete = smtp_session.address_to;

    while (smtp_address_to_delete)
    {
        if (memcmp(smtp_address_to_delete->addr, receiver_addr, strlen(receiver_addr)) == 0)
        {
            //不存在上一个节点，则当前节点为第一个节点
            if (smtp_address_to_last == RT_NULL)
            {
                //若有下一个节点则第一个节点指向待删除的下一个节点，若没有则为空
                smtp_session.address_to = smtp_address_to_delete->next;
                //释放内存
                rt_free(smtp_address_to_delete->addr);
                rt_free(smtp_address_to_delete);

                return 0;
            }
            else
            {
                //若有下一个节点则第一个节点指向待删除的下一个节点，若没有则为空
                smtp_address_to_last->next = smtp_address_to_delete->next;
                //释放内存
                rt_free(smtp_address_to_delete->addr);
                rt_free(smtp_address_to_delete);

                return 0;
            }
        }
        else
        {
            smtp_address_to_last = smtp_address_to_delete;
            smtp_address_to_delete = smtp_address_to_delete->next;
        }
    }
    LOG_W("smtp delete receiver fail, cannot find receiver : %s", receiver_addr);
    return -1;
}
