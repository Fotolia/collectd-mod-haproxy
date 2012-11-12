/**
 * collectd - src/haproxy.c
 * Copyright (C) 2008-2010  Emeric BRUN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Original author:
 *   Emeric BRUN <ebrun at exceliance dot fr>
 * Modified by:
 *   Nicolas SZALAY <nico at rottenbytes dot info>
 **/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"


#define HAP_SOCKETPATH "/var/run/haproxy-stats.sock"
#define HAP_SHOW_STAT "show stat\n"
#define HAP_SHOW_INFO "show info\n"

#define HAP_STAT_LINE_LEN 2047
#define HAP_BYTES 0x0001
#define HAP_SESSIONS 0x0002
#define HAP_ERRORS 0x0004
#define HAP_DENY 0x0008
#define HAP_STATUS 0x0010
#define HAP_HTTP_CODES 0x0020
#define HAP_NONE 0x0000
#define HAP_ALL 0xFFFF

#define HAP_NOTIF_STATUSDOWN 0x0001
#define HAP_NOTIF_STATUSUP 0x0002
#define HAP_NOTIF_NONE 0x0000
#define HAP_NOTIF_ALL 0xFFFF

#define HAP_STATUS_DOWN 0x0000
#define HAP_STATUS_UP 0x0001

static int hap_flags = HAP_ALL;
static int hap_notifs = HAP_NOTIF_NONE;

static char *hap_socketpath = HAP_SOCKETPATH;

/*
 * (Module-)Global variables
 */
static const char *config_keys[] = {
  "DisableBytes",
  "DisableDeny",
  "DisableErrors",
  "DisableSessions",
  "DisableStatus",
  "DisableHttpCodes",
  "NotifStatusDown",
  "NotifStatusUp",
  "PxFilter",
  "SocketPath",
  "SvFilter",
  "RestartGap",
  NULL
};

static int config_keys_num = 11;

static unsigned long hap_restart_gap = 20;

static char **pxf = NULL;
static int pxfcount = 0;

static char **svf = NULL;
static int svfcount = 0;

typedef struct hap_entry {
  char *pxname;
  char *svname;
  unsigned long long bin;
  unsigned long long bout;
  unsigned long long stot;
  unsigned long long rate;
  unsigned long long ereq;
  unsigned long long ersp;
  unsigned long long econ;
  unsigned long long dreq;
  unsigned long long drsp;
  unsigned long long pxtype;
  unsigned long long req_rate;
  unsigned long long hrsp_1xx;
  unsigned long long hrsp_2xx;
  unsigned long long hrsp_3xx;
  unsigned long long hrsp_4xx;
  unsigned long long hrsp_5xx;
  unsigned long long hrsp_other;
  double status;
  struct hap_entry *next;
} hap_entry_t;


typedef struct hap_status {
  char *pxname;
  char *svname;
  int status;
  struct hap_status *next;
} hap_status_t;

static hap_entry_t *hap_entry_list = NULL;
static hap_status_t *hap_status_list = NULL;


static int hap_config(const char *key, const char *value)
{
  if (strcasecmp(key, "DisableDeny") == 0) {
    if IS_TRUE(value)
      hap_flags &= ~(HAP_DENY);
  } else if (strcasecmp(key, "DisableErrors") == 0) {
    if IS_TRUE(value)
      hap_flags &= ~(HAP_ERRORS);
  } else if (strcasecmp(key, "DisableSessions") == 0) {
    if IS_TRUE(value)
      hap_flags &= ~(HAP_SESSIONS);
  } else if (strcasecmp(key, "DisableBytes") == 0) {
    if IS_TRUE(value)
      hap_flags &= ~(HAP_BYTES);
  } else if (strcasecmp(key, "DisableStatus") == 0) {
    if IS_TRUE(value)
      hap_flags &= ~(HAP_STATUS);
  } else if (strcasecmp(key, "DisableHttpCodes") == 0) {
    if IS_TRUE(value)
      hap_flags &= ~(HAP_HTTP_CODES);
  } else if (strcasecmp(key, "NotifStatusDown") == 0) {
    if IS_TRUE(value)
      hap_notifs |= HAP_NOTIF_STATUSDOWN;
  } else if (strcasecmp(key, "NotifStatusUp") == 0) {
    if IS_TRUE(value)
      hap_notifs |= HAP_NOTIF_STATUSUP;
  } else if (strcasecmp(key, "PxFilter") == 0) {
    pxfcount++;
    pxf = realloc(pxf, pxfcount * sizeof(char *));
    pxf[pxfcount - 1] = strdup(value);
  } else if (strcasecmp(key, "SvFilter") == 0) {
    svfcount++;
    svf = realloc(svf, svfcount * sizeof(char *));
    svf[svfcount - 1] = strdup(value);
  } else if (strcasecmp(key, "SocketPath") == 0) {
    hap_socketpath = strdup(value);
  } else if (strcasecmp(key, "RestartGap") == 0) {
    hap_restart_gap = (unsigned long) atol(value);
  } else {
    return (-1);
  }

  return (0);
}

static void hap_submit_counter(const char *svname, const char *pxname,
                               const char *type, int len, ...)
{
  value_t *values;
  va_list ap;
  int i;
  value_list_t vl = VALUE_LIST_INIT;

  values = malloc(len * sizeof(value_t));

  va_start(ap, len);
  for (i = 0; i < len; i++) {
    values[i].counter = va_arg(ap, unsigned long long);
  }
  va_end(ap);

  vl.values = values;
  vl.values_len = len;
  vl.time = 0;
  snprintf(vl.host, sizeof(vl.host), "%s", hostname_g);
  snprintf(vl.plugin, sizeof(vl.plugin), "haproxy");
  snprintf(vl.type_instance, sizeof(vl.type_instance), "%s-%s", svname,
           pxname);
  sstrncpy(vl.type, type, sizeof(vl.type));
  plugin_dispatch_values(&vl);
  free(values);
}

static void hap_notification(const char *svname, const char *pxname, const char *type,
                             int severity, const char *message)
{
  notification_t notif;

  memset(&notif, 0, sizeof(notification_t));
  notif.severity = severity;
  notif.time = time(NULL);
  strncpy(notif.message, message, sizeof(notif.message) - 1);
  strncpy(notif.host, hostname_g, sizeof(notif.host) - 1);
  strncpy(notif.plugin, "haproxy", sizeof(notif.plugin) - 1);
  strncpy(notif.type, type, sizeof(notif.type) - 1);
  snprintf(notif.type_instance, sizeof(notif.type_instance), "%s-%s",
           svname, pxname);
  plugin_dispatch_notification(&notif);
}

static void hap_submit_gauge(const char *svname, const char *pxname, const char *type,
                             int len, ...)
{
  value_t *values;
  va_list ap;
  int i;
  value_list_t vl = VALUE_LIST_INIT;

  values = malloc(len * sizeof(value_t));

  va_start(ap, len);
  for (i = 0; i < len; i++) {
    values[i].gauge = va_arg(ap, double);
  }
  va_end(ap);

  vl.values = values;
  vl.values_len = len;
  vl.time = 0;
  snprintf(vl.host, sizeof(vl.host), "%s", hostname_g);
  snprintf(vl.plugin, sizeof(vl.plugin), "haproxy");
  snprintf(vl.type_instance, sizeof(vl.type_instance), "%s-%s", svname,
           pxname);
  sstrncpy(vl.type, type, sizeof(vl.type));
  plugin_dispatch_values(&vl);
  free(values);
}

static void hap_line2entry(char *line)
{
  char *p, *e;
  int i;
  hap_entry_t *pentry;

  pentry = calloc(1, sizeof(hap_entry_t));

  /* Fields list
    0 => pxname
    1 => svname
    2 => qcur
    3 => qmax
    4 => scur
    5 => smax
    6 => slim
    7 => stot
    8 => bin
    9 => bout
    10 => dreq
    11 => dresp
    12 => ereq
    13 => econ
    14 => eresp
    15 => wretr
    16 => wredis
    17 => status
    18 => weight
    19 => act
    20 => bck
    21 => chkfail
    22 => chkdown
    23 => lastchg
    24 => downtime
    25 => qlimit
    26 => pid
    27 => iid
    28 => sid
    29 => throttle
    30 => lbtot
    31 => tracked
    32 => type
    33 => rate
    34 => rate_lim
    35 => rate_max
    36 => check_status
    37 => check_code
    38 => check_duration
    39 => hrsp_1xx
    40 => hrsp_2xx
    41 => hrsp_3xx
    42 => hrsp_4xx
    43 => hrsp_5xx
    44 => hrsp_other
    45 => hanafail
    46 => req_rate
    47 => req_rate_max
    48 => req_tot
    49 => cli_abrt
    50 => srv_abrt
  */

  e = p = line;
  /* tokenize line */
  for (i = 0; i < 51; i++) {
    while (*e && *e != ',')
      e++;
    if (!*e)
      break;
    *e = 0;
    switch (i) {
    case 0:
      /* filter on proxy */
      pentry->pxname = strdup(p);
      break;
    case 1:
      /* filter on srv */
      pentry->svname = strdup(p);
      break;
    case 4:
      pentry->stot = (unsigned long long) atoll(p) * interval_g;
      break;
    case 8:
      pentry->bin = (unsigned long long) atoll(p);
      break;
    case 9:
      pentry->bout = (unsigned long long) atoll(p);
      break;
    case 10:
      pentry->dreq = (unsigned long long) atoll(p);
      break;
    case 11:
      pentry->drsp = (unsigned long long) atoll(p);
      break;
    case 12:
      pentry->ereq = (unsigned long long) atoll(p);
      break;
    case 13:
      pentry->econ = (unsigned long long) atoll(p);
      break;
    case 14:
      pentry->ersp = (unsigned long long) atoll(p);
      break;
    case 17:
      if (!strncmp(p, "UP", 2)) {
        char *s;

        /* traduct UP x/y fraction to percent if exist, else assume value 100% */
        s = strchr(p + 2, '/');
        if (s && atoi(s + 1)) {
          pentry->status = (100.0F * atoi(p + 2)) / atoi(s + 1);
        } else {
          pentry->status = 100.0F;
        }
      } else if (!strncmp(p, "DOWN", 4)) {
        char *s;

        /* traduct DOWN x/y fraction to percent if exist, else assume value 0% */
        s = strchr(p + 4, '/');
        if (s && atoi(s + 1)) {
          pentry->status = 100.0F - ((100.0F * atoi(p + 4)) / atoi(s + 1));
        } else {
          pentry->status = 0.0F;
        }
      } else if (!strcmp(p, "OPEN")) {
        /* frontend OPEN is considered 100% unavailable */
        pentry->status = 100.0F;
      } else if (!strcmp(p, "no check")) {
        /* server o check is considered 50% available (to avoid invalid notification) */
        pentry->status = 50.0F;
      } else {
        /* consider other cases as unavalable (ex FULL) */
        pentry->status = 0.0F;
      }
      break;
    case 32:
      pentry->pxtype = (unsigned long long) atoll(p);
      break;
    case 33:
      pentry->rate = (unsigned long long) atoll(p) * interval_g;
      break;
    case 39:
      pentry->hrsp_1xx = (unsigned long long) atoll(p);
      break;
    case 40:
      pentry->hrsp_2xx = (unsigned long long) atoll(p);
      break;
    case 41:
      pentry->hrsp_3xx = (unsigned long long) atoll(p);
      break;
    case 42:
      pentry->hrsp_4xx = (unsigned long long) atoll(p);
      break;
    case 43:
      pentry->hrsp_5xx = (unsigned long long) atoll(p);
      break;
    case 44:
      pentry->hrsp_other = (unsigned long long) atoll(p);
      break;
    case 46:
      pentry->req_rate = (unsigned long long) atoll(p);
      break;
    }
    p = ++e;
  }

  if (!pentry->pxname || !pentry->svname) {
    if (pentry->svname)
      free(pentry->svname);
    if (pentry->pxname)
      free(pentry->pxname);

    free(pentry);
    return;
  }

  pentry->next = hap_entry_list;
  hap_entry_list = pentry;
}

static int hap_retrieveuptime(unsigned long *uptime)
{
  int cread = 0;
  int arg = 0;
  int nbkarg = 0;
  int s_fd = -1;
  char buf[HAP_STAT_LINE_LEN + 1];
  struct sockaddr_un address;
  struct pollfd pfd;
  int off = 0;
  char *line;
  char *e;
  int ret = -1;

  *uptime = 0;

  /* create unix socket */
  s_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s_fd == -1) {
    goto err;
  }

  memset(&address, 0, sizeof(struct sockaddr_un));
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path, hap_socketpath, sizeof(address.sun_path));

  arg = fcntl(s_fd, F_GETFL, NULL);
  nbkarg = arg | O_NONBLOCK;
  fcntl(s_fd, F_SETFL, nbkarg);

  if (connect(s_fd, (const struct sockaddr *) &address, sizeof(address))
      < 0) {
    goto err;
  }

  if (send(s_fd, HAP_SHOW_INFO, sizeof(HAP_SHOW_INFO) - 1, 0) <
      (sizeof(HAP_SHOW_INFO) - 1)) {
    goto err;
  }

  fcntl(s_fd, F_SETFL, arg);

  /* retrieve response */
  while (1) {

    pfd.fd = s_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    if (poll(&pfd, 1, 1000) <= 0) {
      goto err;
    }

    cread = recv(s_fd, buf + off, HAP_STAT_LINE_LEN - off, 0);
    if (cread > 0) {
      buf[cread + off] = 0;
      e = line = buf;
      while (*e && *e != '\n')
        e++;
      while (*e) {
        *e = 0;
        if (!strncmp(line, "Uptime_sec:", strlen("Uptime_sec:"))) {
          *uptime = (unsigned long) atol(line + 11);
          ret = 0;
          goto err;
        }
        line = ++e;
        while (*e && *e != '\n')
          e++;
      }
      off = cread + off - (line - buf);
      if (off)
        memmove(buf, line, off);
    } else if (cread < 0) {
      goto err;
    } else {
      break;
    }
  }

err:
  if (s_fd != -1)
    close(s_fd);

  return ret;
}

static int hap_retrievestat(void)
{
  int cread = 0;
  int arg = 0;
  int nbkarg = 0;
  int s_fd = -1;
  char buf[HAP_STAT_LINE_LEN + 1];
  struct sockaddr_un address;
  struct pollfd pfd;
  int off = 0;
  char *line;
  char *e;
  int ret = -1;

  /* create unix socket */
  s_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s_fd == -1) {
    goto err;
  }

  memset(&address, 0, sizeof(struct sockaddr_un));
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path, hap_socketpath, sizeof(address.sun_path));

  arg = fcntl(s_fd, F_GETFL, NULL);
  nbkarg = arg | O_NONBLOCK;
  fcntl(s_fd, F_SETFL, nbkarg);

  if (connect(s_fd, (const struct sockaddr *) &address, sizeof(address))
      < 0) {
    goto err;
  }

  if (send(s_fd, HAP_SHOW_STAT, sizeof(HAP_SHOW_STAT) - 1, 0) <
      (sizeof(HAP_SHOW_STAT) - 1)) {
    goto err;
  }

  fcntl(s_fd, F_SETFL, arg);


  /* retrieve response */
  while (1) {
    pfd.fd = s_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    if (poll(&pfd, 1, 1000) <= 0) {
      goto err;
    }

    cread = recv(s_fd, buf + off, HAP_STAT_LINE_LEN - off, 0);
    if (cread > 0) {

      buf[cread + off] = 0;
      e = line = buf;
      while (*e && *e != '\n')
        e++;
      while (*e) {
        *e = 0;
        if (*line != '#')
          hap_line2entry(line);
        line = ++e;
        while (*e && *e != '\n')
          e++;
      }
      off = cread + off - (line - buf);
      if (off)
        memmove(buf, line, off);

    } else if (cread < 0) {
      goto err;
    } else {
      break;
    }
  }

  ret = 0;

err:
  if (s_fd != -1)
    close(s_fd);

  return ret;
}

hap_status_t *new_hap_status(const char *svname, const char *pxname,
                             int status)
{
  hap_status_t *pstatus;

  if (!svname || !pxname)
    return NULL;

  pstatus = malloc(sizeof(hap_status_t));
  pstatus->svname = strdup(svname);
  pstatus->pxname = strdup(pxname);
  pstatus->status = status;

  pstatus->next = hap_status_list;
  hap_status_list = pstatus;

  return pstatus;
}


hap_status_t *get_hap_status(const char *svname, const char *pxname)
{
  hap_status_t *pstatus;

  pstatus = hap_status_list;
  while (pstatus) {
    if (!strcmp(pstatus->svname, svname) &&
        !strcmp(pstatus->pxname, pxname)) {
      return pstatus;
    }
    pstatus = pstatus->next;
  }

  return NULL;
}

static int hap_read(void)
{
  hap_entry_t *pentry;
  hap_entry_t *pfree;
  hap_status_t *pstatus;
  unsigned long uptime;
  int i;


  if (hap_retrievestat() < 0) {
    goto noreg;
  }

  /* retrieve date after stats to be sure
     haproxy not restarted between the 2 connections */
  if (hap_retrieveuptime(&uptime) < 0) {
    goto noreg;
  }

  /* Haproxy seems to be restarted, waiting Restart Gap + 1sec
     restart_gap should be superior or equal to heartbeat */

  if (uptime < (hap_restart_gap + 1)) {
    goto noreg;
  }

  pentry = hap_entry_list;

  while (pentry) {

    /* in case of status notification */
    if (hap_notifs) {
      /* in case now px/srv is DOWN */
      if (pentry->status == 0.0F) {
        /* search last cached status */
        pstatus = get_hap_status(pentry->svname, pentry->pxname);
        if (!pstatus) {
          /* insert status to cache */
          new_hap_status(pentry->svname, pentry->pxname, HAP_STATUS_DOWN);
        } else if (pstatus->status != HAP_STATUS_DOWN) {
          /* notify ? */
          if (hap_notifs & HAP_NOTIF_STATUSDOWN) {
            hap_notification(pentry->svname, pentry->pxname,
                             "hap_status", NOTIF_WARNING, "DOWN");
          }
          /* update status into cache */
          pstatus->status = HAP_STATUS_DOWN;
        }
      } else if (pentry->status == 100.0F) {
        /* roll it inverse in UP case */
        pstatus = get_hap_status(pentry->svname, pentry->pxname);
        if (!pstatus) {
          new_hap_status(pentry->svname, pentry->pxname, HAP_STATUS_UP);
        } else if (pstatus->status != HAP_STATUS_UP) {

          if (hap_notifs & HAP_NOTIF_STATUSUP) {
            hap_notification(pentry->svname, pentry->pxname,
                             "hap_status", NOTIF_OKAY, "UP");
          }
          pstatus->status = HAP_STATUS_UP;
        }
      }
    }

    /* filter on proxy */
    if (pxf) {
      for (i = 0; i < pxfcount; i++) {
        if (!strcasecmp(pxf[i], pentry->pxname)) {
          break;
        }
      }
      if (i == pxfcount) {
        goto filtered;
      }
    }

    /* filter on server */
    if (svf) {
      for (i = 0; i < svfcount; i++) {
        if (!strcasecmp(svf[i], pentry->svname)) {
          break;
        }
      }
      if (i == svfcount) {
        goto filtered;
      }
    }

    if (hap_flags & HAP_BYTES) {
      hap_submit_counter(pentry->svname, pentry->pxname, "hap_bytes",
                         2, pentry->bin, pentry->bout);
    }

    if (hap_flags & HAP_SESSIONS) {
      hap_submit_counter(pentry->svname, pentry->pxname,
                         "hap_sessions", 2, pentry->stot, pentry->rate);
      hap_submit_gauge(pentry->svname, pentry->pxname,
                       "frequency", 1, pentry->req_rate);
    }

    if (hap_flags & HAP_ERRORS) {
      hap_submit_counter(pentry->svname, pentry->pxname,
                         "hap_errors", 3, pentry->ereq, pentry->ersp,
                         pentry->econ);
    }

    if (hap_flags & HAP_HTTP_CODES) {
      /* submit only for the frontend, backends and servers (not sockets) */
      if (pentry->pxtype < 3) {
        hap_submit_counter(pentry->svname, pentry->pxname,
                          "hap_http_codes", 6, pentry->hrsp_1xx,
                          pentry->hrsp_2xx, pentry->hrsp_3xx, pentry->hrsp_4xx,
                          pentry->hrsp_5xx, pentry->hrsp_other);
      }
    }

    if (hap_flags & HAP_DENY) {
      hap_submit_counter(pentry->svname, pentry->pxname, "hap_deny",
                         2, pentry->dreq, pentry->drsp);
    }

    if (hap_flags & HAP_STATUS) {
      hap_submit_gauge(pentry->svname, pentry->pxname, "hap_status",
                       1, pentry->status);
    }
  filtered:

    pfree = pentry;
    pentry = pentry->next;

    if (pfree->pxname)
      free(pfree->pxname);
    if (pfree->svname)
      free(pfree->svname);

    free(pfree);

  }

  hap_entry_list = NULL;

  return 0;

noreg:
  pentry = hap_entry_list;

  while (pentry) {
    pfree = pentry;
    pentry = pentry->next;

    /* free rrd-registered entry */
    if (pfree->pxname)
      free(pfree->pxname);
    if (pfree->svname)
      free(pfree->svname);

    free(pfree);
  }

  hap_entry_list = NULL;

  return 0;
}


void module_register(void)
{
  plugin_register_config("haproxy", hap_config,
                         config_keys, config_keys_num);
  plugin_register_read("haproxy", hap_read);
}
