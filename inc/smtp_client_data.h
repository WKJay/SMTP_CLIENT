#ifndef __SMTP_DATA_H
#define __SMTP_DATA_H

#include <stdint.h>

uint32_t smtp_base64_encode(char *target, uint32_t target_len, const char *source, uint32_t source_len);

#endif /* __SMTP_DATA_H */
