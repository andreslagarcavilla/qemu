/*
 * QEMU Guest Agent common/cross-platform command implementations
 *
 * Copyright IBM Corp. 2012
 *
 * Authors:
 *  Michael Roth      <mdroth@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <glib.h>
#include <linux/random.h>
#include <sys/ioctl.h>
#include "qga/guest-agent-core.h"
#include "qga-qmp-commands.h"
#include "qapi/qmp/qerror.h"

/* Note: in some situations, like with the fsfreeze, logging may be
 * temporarilly disabled. if it is necessary that a command be able
 * to log for accounting purposes, check ga_logging_enabled() beforehand,
 * and use the QERR_QGA_LOGGING_DISABLED to generate an error
 */
void slog(const gchar *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    g_logv("syslog", G_LOG_LEVEL_INFO, fmt, ap);
    va_end(ap);
}

int64_t qmp_guest_sync_delimited(int64_t id, Error **errp)
{
    ga_set_response_delimited(ga_state);
    return id;
}

int64_t qmp_guest_sync(int64_t id, Error **errp)
{
    return id;
}

void qmp_guest_ping(Error **err)
{
    slog("guest-ping called");
}

void qmp_guest_privacy_reset(const char *seed, Error **errp)
{
    int fd;

    slog("guest-privacy-reset start");

    /* All of the below best effort. Hence the macro wrapper to effectively
     * ignore return values of syscalls glibc does not want you to ignore. */
#define IGNORE_RC(f) if (f == 0) {}

    /* Reset random entropy. */
    fd = open("/dev/urandom", O_WRONLY);
    if ( fd >= 0 )
    {
        ioctl(fd, RNDCLEARPOOL);
        IGNORE_RC(write(fd, seed, strlen(seed)));
        close(fd);
    }
    fd = open("/dev/random", O_WRONLY);
    if ( fd >= 0 )
    {
        ioctl(fd, RNDCLEARPOOL);
        IGNORE_RC(write(fd, seed, strlen(seed)));
        close(fd);
    }

    /* Fry ssh host keys, replace with fresh ones *after* randomness reset. */
    unlink("/etc/ssh/ssh_host_key");
    unlink("/etc/ssh/ssh_host_key.pub");
    unlink("/etc/ssh/ssh_host_rsa_key");
    unlink("/etc/ssh/ssh_host_rsa_key.pub");
    unlink("/etc/ssh/ssh_host_dsa_key");
    unlink("/etc/ssh/ssh_host_dsa_key.pub");
    IGNORE_RC(system("ssh-keygen -N '' -t rsa1 -f /etc/ssh/ssh_host_key"));
    IGNORE_RC(system("ssh-keygen -N '' -t rsa -f /etc/ssh/ssh_host_rsa_key"));
    IGNORE_RC(system("ssh-keygen -N '' -t dsa -f /etc/ssh/ssh_host_dsa_key"));
    IGNORE_RC(system("service sshd restart"));

    /* Restart eth-based *physical* network interfaces, they may have been
     * replugged with different nics. Note that dhclient will reset hostname in
     * most scenarios. */
    IGNORE_RC(system("find /sys/class/net -type l -exec test -L {}/device \\; -print | xargs -n1 basename | xargs -n1 ifdown"));
    IGNORE_RC(system("find /sys/class/net -type l -exec test -L {}/device \\; -print | xargs -n1 basename | xargs -n1 ifup"));
    /* If there is a network service it needs kicking (centos). */
    IGNORE_RC(system("bash -c '[ -f /etc/init.d/network ] && service network restart'"));

    slog("guest-privacy-reset finish");
}

struct GuestAgentInfo *qmp_guest_info(Error **err)
{
    GuestAgentInfo *info = g_malloc0(sizeof(GuestAgentInfo));
    GuestAgentCommandInfo *cmd_info;
    GuestAgentCommandInfoList *cmd_info_list;
    char **cmd_list_head, **cmd_list;

    info->version = g_strdup(QEMU_VERSION);

    cmd_list_head = cmd_list = qmp_get_command_list();
    if (*cmd_list_head == NULL) {
        goto out;
    }

    while (*cmd_list) {
        cmd_info = g_malloc0(sizeof(GuestAgentCommandInfo));
        cmd_info->name = g_strdup(*cmd_list);
        cmd_info->enabled = qmp_command_is_enabled(cmd_info->name);

        cmd_info_list = g_malloc0(sizeof(GuestAgentCommandInfoList));
        cmd_info_list->value = cmd_info;
        cmd_info_list->next = info->supported_commands;
        info->supported_commands = cmd_info_list;

        g_free(*cmd_list);
        cmd_list++;
    }

out:
    g_free(cmd_list_head);
    return info;
}
