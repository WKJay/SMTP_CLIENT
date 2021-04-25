#ifndef __SMTP_PRIVATE_H
#define __SMTP_PRIVATE_H
#include <stdint.h>
#include <rtthread.h>

//调试配置
#ifdef SMTP_CLIENT_ENABLE_DEBUG_LOG
#define DBG_ENABLE
#define DBG_LEVEL 3
#define DBG_COLOR
#define DBG_SECTION_NAME "SMTP"
#endif
#include "rtdbg.h"

#ifdef SMTP_CLIENT_USING_TLS
#include <tls_certificate.h>
#include <tls_client.h>
#endif

#ifdef SMTP_CLIENT_USING_ATTACHMENT
#include <dfs_posix.h>
#endif

#define SMTP_MAX_ADDR_LEN 100
#define SMTP_MAX_AUTH_LEN 50
#define SMTP_MAX_FILE_PATH_LEN 64
#define SMTP_ATTACHMENT_MAX_NAME_LEN 32
#define SMTP_SEND_CMD_MAX_LEN 100
#define SMTP_SEND_DATA_HEAD_MAX_LENGTH 256
#define SMTP_SEND_DATA_MAX_LEN 512
#define SMTP_RESPONSE_MAX_LEN 512
#define SMTP_MAX_ATTACHMENTS 20

#ifdef SMTP_CLIENT_USING_TLS
//缓冲区大小
#define MBEDTLS_READ_BUFFER_LEN 1024
#endif

//smtp 会话阶段
enum smtp_session_state
{
    SMTP_NULL,
    SMTP_HELO,
    SMTP_START_TLS,
    SMTP_FINISH_START_TLS,
    SMTP_AUTH_LOGIN,
    SMTP_MAIL,
    SMTP_RCPT,
    SMTP_DATA,
    SMTP_BODY,
    SMTP_QUIT,
    SMTP_CLOSED
};

//smtp收件人链表
typedef struct _smtp_address_to
{
    char *addr;
    struct _smtp_address_to *next;
} smtp_address_to_t;

//smtp附件链
typedef struct _smtp_attachments
{
    char file_path[SMTP_MAX_FILE_PATH_LEN];
    char file_name[SMTP_ATTACHMENT_MAX_NAME_LEN];
    struct _smtp_attachments *next;
} smtp_attachments_t;

//smtp 会话结构
typedef struct
{
    //会话状态
    enum smtp_session_state state;
    //会话超时时间，如果时间为0，标志超时，则自动关闭连接
    uint16_t timer;
    //smtp服务器域名
    char *server_domain;
    //smtp服务器ip
    char *server_ip;
    //smtp服务器端口号
    char *server_port;
    //用户名
    char username[SMTP_MAX_AUTH_LEN * 2];
    //密码(有些邮箱服务器需要的是用户凭据)
    char password[SMTP_MAX_AUTH_LEN * 2];
    //邮件源地址
    char address_from[SMTP_MAX_ADDR_LEN];
    //邮件目的地址
    smtp_address_to_t *address_to;
    //邮件主题
    char *subject;
    //邮件内容
    char *body;
    //smtp连接句柄
    int conn_fd;
#ifdef SMTP_CLIENT_USING_ATTACHMENT
    smtp_attachments_t *attachments;
#endif
#ifdef SMTP_CLIENT_USING_TLS
    //tls会话
    MbedTLSSession *tls_session;
#endif
} smtp_session_t;

extern smtp_session_t smtp_session;

#define SMTP_RESP_220 "220"
#define SMTP_RESP_235 "235"
#define SMTP_RESP_250 "250"
#define SMTP_RESP_334 "334"
#define SMTP_RESP_354 "354"
#define SMTP_RESP_LOGIN_UNAME "VXNlcm5hbWU6"
#define SMTP_RESP_LOGIN_PASS "UGFzc3dvcmQ6"
#define SMTP_MAIL_BOUNDARY "smtp_client_boundary"

#define SMTP_CMD_EHLO "EHLO DM11\r\n"
#define SMTP_CMD_AUTHLOGIN "AUTH LOGIN\r\n"
#define SMTP_CMD_STARTTLS "STARTTLS\r\n"
#define SMTP_CMD_MAIL_HEAD "MAIL FROM: <"
#define SMTP_CMD_MAIL_END ">\r\n"
#define SMTP_CMD_RCPT_HEAD "RCPT TO: <"
#define SMTP_CMD_RCPT_END ">\r\n"
#define SMTP_CMD_DATA "DATA\r\n"
#define SMTP_CMD_HEADER_1 "From: <"
#define SMTP_CMD_HEADER_2 ">\r\nTo: <"
#define SMTP_CMD_HEADER_3 ">\r\nSubject: "
#define SMTP_CMD_HEADER_4 "\r\n\r\n"
#define SMTP_CMD_BODY_FINISHED "\r\n.\r\n"
#define SMTP_CMD_QUIT "QUIT\r\n"

#ifdef SMTP_CLIENT_USING_TLS
//向SSL/TLS中写入数据
int smtp_mbedtls_client_write(MbedTLSSession *tls_session, uint8_t *buf, uint32_t len);
//从 SSL/TLS 中读取数据
int smtp_mbedtls_client_read(MbedTLSSession *tls_session, char *buf, size_t len);

//smtp mbedtls 网络连接（用于starttls方式）
int smtp_connect_server_by_starttls(void);
//开启starttls
int smtp_mbedtls_starttls(MbedTLSSession *tls_session);
//smtp 以tls加密方式连接服务器
int smtp_connect_server_by_tls(void);
//smtp 关闭tls连接，释放资源
int smtp_mbedtls_close_connection(void);
#endif

#endif /* __SMTP_PRIVATE_H */
