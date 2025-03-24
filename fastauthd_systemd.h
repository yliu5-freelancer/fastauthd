#ifndef _FASTAUTHD_SYSTEMD_H
#define _FASTAUTHD_SYSTEMD_H

#include <systemd/sd-daemon.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

static inline void
SYSLOG_WRAPPER(int foreground, int log_level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    if (foreground) {
        vprintf(fmt, args);
    } else {
        vsyslog(log_level, fmt, args);
    }

    va_end(args);
}
int notify_systemd_ready();
int notify_systemd_status(char *status);

#endif