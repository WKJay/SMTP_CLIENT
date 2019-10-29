/*************************************************
 Copyright (c) 2019
 All rights reserved.
 File name:     smtp_client_data.c
 Description:   smtp 数据处理源文件
 History:
 1. Version:    
    Date:       2019-10-10
    Author:     wangjunjie
    Modify:     
*************************************************/

#include <stdint.h>
#include "smtp_client_private.h"

const uint8_t smtp_base64_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '+', '/'};

/**
 * Name:    smtp_base64_encode
 * Brief:   base64加密
 * Input:
 *  @target:加密数据存储位置
 *  @target_len:存储区的长度
 *  @source:原始数据
 *  @source_len：原始数据长度
 * Output:  加密后数据的长度,出错返回0
 */
uint32_t
smtp_base64_encode(char *target, uint32_t target_len, const char *source, uint32_t source_len)
{
    uint32_t i;
    int8_t j;
    uint32_t target_idx = 0;
    uint32_t longer = (3 - (source_len % 3) == 3) ? 0 : (3 - (source_len % 3));
    uint32_t source_len_b64 = source_len + longer;
    uint32_t len = (((source_len_b64)*4) / 3);
    uint8_t x = 5;
    uint8_t current = 0;

    if (target_len < len)
    {
        LOG_E(">target_len is too short");
        return 0;
    }

    for (i = 0; i < source_len_b64; i++)
    {
        uint8_t b = (i < source_len ? source[i] : 0);
        for (j = 7; j >= 0; j--, x--)
        {
            uint8_t shift = ((b & (1 << j)) != 0) ? 1 : 0;
            current |= shift << x;
            if (x == 0)
            {
                target[target_idx++] = smtp_base64_table[current];
                x = 6;
                current = 0;
            }
        }
    }

    for (i = len - longer; i < len; i++)
    {
        target[i] = '=';
    }

    return len;
}
