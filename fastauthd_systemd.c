#include "fastauthd_systemd.h"

int notify_systemd_ready()
{
    return sd_notify(0, "READY=1");
}

int notify_systemd_status(char *status)
{
    if (!status)
        return sd_notifyf(0, "STATUS=%s", status);
    return -1;
}