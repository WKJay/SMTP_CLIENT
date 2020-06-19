/*************************************************
 Copyright (c) 2019
 All rights reserved.
 File name:     smtp_client_tls.c
 Description:   
 History:
 1. Version:    
    Date:       2019-10-12
    Author:     wangjunjie
    Modify:     
*************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rtthread.h>

#include "smtp_client_private.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

/**
 * Name:    smtp_mbedtls_context_create
 * Brief:   创建smtp加密环境
 * Input:
 *  @smtp_session:  smtp会话
 * Output:  成功返回tls会话，失败返回NULL并释放tls资源
 */
static MbedTLSSession *smtp_mbedtls_context_create(smtp_session_t *smtp_session)
{
    MbedTLSSession *tls_session = RT_NULL;

    tls_session = (MbedTLSSession *)tls_malloc(sizeof(MbedTLSSession));
    if (tls_session == RT_NULL)
    {
        LOG_E(">No memory for MbedTLS session object");
        return NULL;
    }
    rt_memset(tls_session, 0x0, sizeof(MbedTLSSession));

    //拷贝服务器地址
    if (smtp_session->server_ip)
    {
        tls_session->host = tls_strdup(smtp_session->server_ip);
    }
    else if (smtp_session->server_domain)
    {
        tls_session->host = tls_strdup(smtp_session->server_domain);
    }
    else
    {
        LOG_E(">cannot find server ip or domain");
        tls_free(tls_session);
        return NULL;
    }
    //拷贝服务器端口
    if (smtp_session->server_port)
    {
        tls_session->port = tls_strdup(smtp_session->server_port);
    }
    else
    {
        LOG_E(">cannot find server port");
        if (tls_session->host)
        {
            tls_free(tls_session->host);
        }
        tls_free(tls_session);
        return NULL;
    }
    //分配数据接收缓冲区
    tls_session->buffer_len = MBEDTLS_READ_BUFFER_LEN;
    tls_session->buffer = tls_malloc(tls_session->buffer_len);
    memset(tls_session->buffer, 0, MBEDTLS_READ_BUFFER_LEN);
    if (tls_session->buffer == RT_NULL)
    {
        LOG_E(">no memory for MbedTLS buffer");
        if (tls_session->host)
        {
            tls_free(tls_session->host);
        }
        if (tls_session->port)
        {
            tls_free(tls_session->port);
        }
        tls_free(tls_session);
        return NULL;
    }
    return tls_session;
}

/**
 * Name:    smtp_mbedtls_client_init
 * Brief:   初始化 TLS 客户端
 * Input:
 *  @smtp_session:  smtp会话
 * Output:  成功返回0，失败返回-1并关闭tls连接
 */
static int smtp_mbedtls_client_init(MbedTLSSession *tls_session)
{
    //设置随机字符串种子
    char *pers = "hello_smtp";
    int result = -1;

    if ((result = mbedtls_client_init(tls_session, (void *)pers, strlen(pers))) != 0)
    {
        LOG_E(">MbedTLSClientInit err return : -0x%x", -result);
        mbedtls_client_close(tls_session);
        LOG_I(">MbedTLS connection close");
        return -1;
    }
    return result;
}

/**
 * Name:    smtp_mbedtls_client_context
 * Brief:   初始化 SSL/TLS 客户端上下文
 * Input:
 *  @smtp_session:  smtp会话
 * Output:  成功返回0，失败返回-1并关闭tls连接
 */
static int smtp_mbedtls_client_context(MbedTLSSession *tls_session)
{
    int result = -1;
    if ((result = mbedtls_client_context(tls_session)) < 0)
    {
        LOG_E(">MbedTLSCLlientContext  err return : -0x%x", -result);
        mbedtls_client_close(tls_session);
        LOG_I(">MbedTLS connection close");
        return -1;
    }
    return result;
}

/**
 * Name:    smtp_mbedtls_client_connect
 * Brief:   建立 SSL/TLS 连接
 * Input:
 *  @smtp_session:  smtp会话
 * Output:  成功返回0，失败返回-1并关闭tls连接
 */
static int smtp_mbedtls_client_connect(MbedTLSSession *tls_session)
{
    int result = -1;
    if ((result = mbedtls_client_connect(tls_session)) != 0)
    {
        LOG_E(">MbedTLSCLlientConnect   err return : -0x%x", -result);
        mbedtls_client_close(tls_session);
        LOG_I(">MbedTLS connection close");
        return -1;
    }
    return result;
}

/**
 * Name:    smtp_mbedtls_client_write
 * Brief:   向SSL/TLS中写入数据
 * Input:
 *  @smtp_session:  smtp会话
 *  @buf:           写入的字符串
 *  @len:           写入长度
 * Output:  成功写入的字符个数，失败返回-1或0并关闭tls连接
 */
int smtp_mbedtls_client_write(MbedTLSSession *tls_session, uint8_t *buf, uint32_t len)
{
    int result = -1;
    while ((result = mbedtls_client_write(tls_session, (const unsigned char *)buf, len)) <= 0)
    {
        if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            LOG_E(">mbedtls_ssl_write  err return : -0x%x", -result);
            return -1;
        }
    }
    return result;
}

/**
 * Name:    smtp_mbedtls_client_read
 * Brief:   从 SSL/TLS 中读取数据
 * Input:
 *  @smtp_session:  smtp会话
 * Output:  成功读取的字符个数，失败返回-1并关闭tls连接
 */
int smtp_mbedtls_client_read(MbedTLSSession *tls_session, char *buf, size_t len)
{
    int result = -1;
    memset(buf, 0x00, len);
    result = mbedtls_client_read(tls_session, (unsigned char *)buf, len);
    if (result < 0)
    {
        LOG_E(">mbedtls_ssl_read returned -0x%x", -result);
    }
    if (result == 0)
    {
        LOG_E(">connection closed");
    }
    return result;
}

/**
 * Name:    smtp_mbedtls_starttls
 * Brief:   开启starttls
 * Input:
 *  @tls_session:   smtp会话
 * Output:  成功返回0，失败返回-1并关闭连接
 */
int smtp_mbedtls_starttls(MbedTLSSession *tls_session)
{
    int result = -1;
    //设置网络操作接口
    mbedtls_ssl_set_bio(&tls_session->ssl, &tls_session->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    //TLS握手
    while ((result = mbedtls_ssl_handshake(&tls_session->ssl)) != 0)
    {
        if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            LOG_E(">smtp mbedtls handshake fail");
            mbedtls_client_close(tls_session);
            LOG_I(">MbedTLS connection close");
            return -1;
        }
    }
    //证书验证
    result = mbedtls_ssl_get_verify_result(&tls_session->ssl);
    if (result != 0)
    {
        memset(tls_session->buffer, 0x00, tls_session->buffer_len);
        mbedtls_x509_crt_verify_info((char *)tls_session->buffer, tls_session->buffer_len, "  ! ", result);
        LOG_E(">smtp mbedtls crt verify fail");
        mbedtls_client_close(tls_session);
        LOG_I(">MbedTLS connection close");
        return -1;
    }
    return result;
}

/**
 * Name:    smtp_connect_server_by_tls
 * Brief:   smtp 以tls加密方式连接服务器
 * Input:   None
 * Output:  成功返回0，失败返回-1
 */
int smtp_connect_server_by_tls(void)
{
    int result = -1;
    //初始化TLS会话
    smtp_session.tls_session = smtp_mbedtls_context_create(&smtp_session);
    if (smtp_session.tls_session == NULL)
    {
        return -1;
    }
    //初始化TLS/SSL客户端
    result = smtp_mbedtls_client_init(smtp_session.tls_session);
    if (result != 0)
    {
        return -1;
    }
    //初始化 SSL/TLS 客户端上下文
    result = smtp_mbedtls_client_context(smtp_session.tls_session);
    if (result != 0)
    {
        return -1;
    }
    //建立ssl连接
    result = smtp_mbedtls_client_connect(smtp_session.tls_session);
    if (result != 0)
    {
        return -1;
    }
    smtp_session.conn_fd = smtp_session.tls_session->server_fd.fd;
    return result;
}

/**
 * Name:    smtp_connect_server_by_starttls
 * Brief:   smtp mbedtls 网络连接（用于starttls方式）
 * Input:   None
 * Output:  成功返回0，失败返回-1并释放资源
 */
int smtp_connect_server_by_starttls(void)
{
    int result = -1;
    //初始化TLS会话
    smtp_session.tls_session = smtp_mbedtls_context_create(&smtp_session);
    if (smtp_session.tls_session == NULL)
    {
        return -1;
    }
    //初始化TLS/SSL客户端
    result = smtp_mbedtls_client_init(smtp_session.tls_session);
    if (result != 0)
    {
        return -1;
    }
    //初始化 SSL/TLS 客户端上下文
    result = smtp_mbedtls_client_context(smtp_session.tls_session);
    if (result != 0)
    {
        return -1;
    }

    result = mbedtls_net_connect(&smtp_session.tls_session->server_fd, smtp_session.tls_session->host,
                                 smtp_session.tls_session->port, MBEDTLS_NET_PROTO_TCP);

    if (result != 0)
    {
        LOG_E(">smtp mbedtls net connect fail");
        mbedtls_client_close(smtp_session.tls_session);
    }
    smtp_session.conn_fd = smtp_session.tls_session->server_fd.fd;
    return result;
}

/**
 * Name:    smtp_mbedtls_close_connection
 * Brief:   smtp 关闭tls连接，释放资源
 * Input:   None
 * Output:  成功返回0，失败返回-1
 */
int smtp_mbedtls_close_connection(void)
{
    int result = -1;
    if (smtp_session.tls_session)
    {
        result = mbedtls_client_close(smtp_session.tls_session);
        if (result == 0)
        {
            smtp_session.tls_session = NULL;
        }
        else
        {
            LOG_E(">smtp tls session free fail!");
        }
        return result;
    }
    else
    {
        return 0;
    }
}
