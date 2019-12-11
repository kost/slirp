/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>

#ifdef USE_PPP
#include "ppp/ppp.h"
#include "ppp/pppd.h"
#include "ppp/pathnames.h"
#include "ppp/patchlevel.h"
#include "ppp/fsm.h"
#include "ppp/lcp.h"
#include "ppp/ipcp.h"
#include "ppp/upap.h"
#include "ppp/chap.h"
#include "ppp/ccp.h"
#include "ppp/ppp-comp.h"

#define FALSE	0
#define TRUE	1

#ifndef GIDSET_TYPE
#define GIDSET_TYPE	int
#endif

void readable _P((int fd));

/*
 * Option variables
 */
int     debug = 0;              /* Debug flag */
int     kdebugflag = 0;         /* Tell kernel to print debug messages */
int     default_device = 1;     /* Using /dev/tty or equivalent */
char    devnam[MAXPATHLEN] = "/dev/tty";        /* Device name */
int     crtscts = 0;            /* Use hardware flow control */
int     modem = 1;              /* Use modem control lines */
int     inspeed = 0;            /* Input/Output speed requested */
u_int32_t netmask = 0;          /* IP netmask to set on interface */
int     lockflag = 0;           /* Create lock file to lock the serial dev */
int     nodetach = 0;           /* Don't detach from controlling tty */
char    *connector = NULL;      /* Script to establish physical link */
char    *disconnector = NULL;   /* Script to disestablish physical link */
char    user[MAXNAMELEN];       /* Username for PAP */
char    passwd[MAXSECRETLEN];   /* Password for PAP */
int     auth_required = 0;      /* Peer is required to authenticate */
int     defaultroute = 0;       /* assign default route through interface */
int     proxyarp = 0;           /* Set up proxy ARP entry for peer */
int     persist = 0;            /* Reopen link after it goes down */
int     uselogin = 0;           /* Use /etc/passwd for checking PAP */
int     lcp_echo_interval = 0;  /* Interval between LCP echo-requests */
int     lcp_echo_fails = 0;     /* Tolerance to unanswered echo-requests */
char    our_name[MAXNAMELEN];   /* Our name for authentication purposes */
char    remote_name[MAXNAMELEN]; /* Peer's name for authentication */
int     usehostname = 0;        /* Use hostname for our_name */
int     disable_defaultip = 0;  /* Don't use hostname for default IP adrs */
char    *ipparam = NULL;        /* Extra parameter for ip up/down scripts */
int     cryptpap;               /* Passwords in pap-secrets are encrypted */

#ifndef IMPLEMENTATION
#define IMPLEMENTATION ""
#endif

#endif


int     nozeros;                /* If set, 5 0's will not terminate link...*/


/*
 * Read the config file
 */

int (*lprint_print) _P((void *, const char *format, va_list));
char *lprint_ptr, *lprint_ptr2, **lprint_arg;
struct sbuf *lprint_sb;

int cfg_unit;
int ctl_password_ok;
char *ctl_password;

void
config(file, unit)
	char *file;
	int unit;
{
	FILE *cfg;
	char buff[256];
	
	cfg = fopen(file, "r");
	if (cfg == NULL)
	   return;
	
	cfg_unit = unit;
	
	lprint("Reading config file: %s\r\n", file);
	
	while(fgets(buff, 256, cfg) != NULL)
	   do_config(buff, (struct socket *)0, PRN_STDERR);
   	fclose(cfg);
}

int
do_config(buff, inso, type)
	char *buff;
	struct socket *inso;
	int type;
{
	int str_len, i = 0, is_sprintf = 0;
	
	switch (type) {
	 case PRN_STDERR:
		lprint_print = (int (*) _P((void *, const char *, va_list)))vfprintf;
		lprint_ptr2 = (char *)stderr;
		lprint_arg = (char **)&lprint_ptr2;
		break;
	 case PRN_SPRINTF:
		lprint_print = (int (*) _P((void *, const char *, va_list)))vsprintf;
		lprint_sb = &inso->so_snd;
		lprint_ptr2 = lprint_sb->sb_wptr;
		lprint_ptr = lprint_sb->sb_wptr;
		lprint_arg = (char **)&lprint_ptr;
		is_sprintf = 1;
		break;
	 default:
		return 0;
	}
	
	/* Remove any whitespace */
	while (*buff == ' ' || *buff == '\t')
		buff++;
	
	/* Ignore if it's a comment, or it's an empty line */
	if (*buff == '#' || *buff == '\r' || *buff == '\n' || *buff == 0)
		return 0;
	
	while (cfg[i].command) {
		if ((((str_len = strlen(cfg[i].command)) && !strncmp(buff, cfg[i].command, str_len)) ||
		     (cfg[i].command_line && (str_len = strlen(cfg[i].command_line)) &&
		      !strncmp(buff, cfg[i].command_line, str_len))) &&
		    (buff[str_len] == ' ' || buff[str_len] == '\t' ||
		     buff[str_len] == '\n' || buff[str_len] == '\r' ||
		     buff[str_len] == 0)) {
			while (buff[str_len] == ' ' || buff[str_len] == '\t')
			   str_len++;
			if (buff[str_len] == '\n' || buff[str_len] == '\r')
			   buff[str_len] = 0;
			if (cfg[i].type & type) {
				if ((cfg[i].flags & CFG_NEEDARG) && buff[str_len] == 0) {
					lprint("Error: Insufficient arguments to \"%s\".\r\n", buff);
					goto done;
				}
				if ((*cfg[i].func)((buff[str_len]?buff+str_len:(char *)0), inso) == CFG_BADARGS)
				   lprint("Error: Usage: %s %s\r\n", cfg[i].command, cfg[i].usage_args);
				goto done;
			} else {
				lprint("Error: Option unavailable from %s.\r\n",
						(type == PRN_STDERR)?"config file/command line":
								     "telnet");
				goto done;
			}
		}
		i++;
	}
	/* Command failed */
	lprint("Error: Bad command: %s", buff);
	if (inso)
	   lprint("\r\n");
done:
	if (do_echo)
	   lprint("\r");
	
	if (is_sprintf)
	   lprint_print = 0;
	
	if (lprint_sb) {
		i = lprint_ptr - lprint_sb->sb_wptr;
		lprint_sb = 0;
		return i;
	} else
		return 0;
}

int
get_port(buff, proto_tcp)
	char *buff;
	int proto_tcp;
{
	int x;
	struct servent *servp;
	
	if (!(x = atoi(buff))) {
		/* Must be a service */
		servp = getservbyname(buff, proto_tcp==1?"tcp":"udp");
		if (!servp) {
			lprint("Error: Unknown service: %s\r\n", buff);
			return -1;
		}
		x = ntohs(servp->s_port);
	}
	
	return x;
}

int
cfg_redir_x(buff, inso)
	char *buff;
	struct socket *inso;
{
	u_int32_t laddr = 0;
	int display = 0;
	int screen = 0;
	int start_port = 0;
	char *ptr = 0;

	if (buff) {
		if (strncmp(buff, "start", 5) == 0) {
			buff += 5;
			while (*buff == ' ' || *buff == '\t')
				buff++;
			start_port = strtol(buff, &ptr, 10);
			if (buff == ptr)
				return CFG_BADARGS;
			buff = ptr;
			while (*buff == ' ' || *buff == '\t')
				buff++;
		}

		if ((ptr = strchr(buff, ':'))) {
			*ptr++ = 0;
			if (*ptr == 0)
			   return CFG_BADARGS;
		}
		
		if (buff[0]) {
			laddr = inet_addr(buff);
			if (laddr == 0xffffffff) {
				lprint("Error: bad address\r\n");
				return CFG_ERROR;
			}
		}
		
		if (ptr) {
			if (strchr(ptr, '.')) {
				if (sscanf(ptr, "%d.%d", &display, &screen) != 2)
				   return CFG_BADARGS;
			} else {
				if (sscanf(ptr, "%d", &display) != 1)
				   return CFG_BADARGS;
			}
		}
	}

	if (!laddr) {
		if (inso)
		   laddr = inso->so_laddr.s_addr;
		else
		   laddr = inet_addr(CTL_LOCAL);
	}
	
	redir_x(laddr, start_port, display, screen);
	
	return CFG_OK;
}

int
cfg_setunit(buff, inso)
	char *buff;
	struct socket *inso;
{
	int x;
	
	x = atoi(buff);
	
	if (x < 0 || x >= MAX_INTERFACES) {
		lprint("Error: unit out of range\r\n");
		return CFG_ERROR;
	}
	
	if (!ttys_unit[x]) {
		lprint("Error: no such unit\r\n");
		return CFG_ERROR;
	}
	
	cfg_unit = x;
	lprint("Configuring unit %d\r\n", cfg_unit);
	
	return CFG_OK;
}

int
cfg_redir(buff, inso)
	char *buff;
	struct socket *inso;
{
	u_int32_t laddr;
	int port = 0, lport;
	char str[256];
	char str2[256];
	int once_time = 0, proto_tcp = -1;
	struct socket *so;
	
	if (strncmp(buff, "once", 4) == 0) {
		once_time = SS_FACCEPTONCE;
		proto_tcp = 1;
		buff += 4;
	} else if (strncmp(buff, "time", 4) == 0) {
		once_time = SS_FACCEPTONCE;
		proto_tcp = 0;
		buff += 4;
	}
	
	while (*buff == ' ' || *buff == '\t')
		buff++;
	
	if (strncmp(buff, "tcp", 3) == 0) {
		if (proto_tcp == 0) {
			lprint("Error: TCP redirections can't timeout (yet)\r\n");
			return CFG_ERROR;
		}
		proto_tcp = 1;
		buff += 3;
	} else if (strncmp(buff, "udp", 3) == 0) {
		if (proto_tcp == 1) {
			lprint("Error: UDP redirections can't redirect only once (yet)\r\n");
			return CFG_ERROR;
		}
		proto_tcp = 0;
		buff += 3;
	}
	
	while (*buff == ' ' || *buff == '\t')
	   buff++;
	
	/* If we can't infer the protocol, assume tcp */
	if (proto_tcp == -1)
	   proto_tcp = 1;
	
	if (sscanf(buff, "%d%*[to \t]%256[^:]:%256s", &port, str, str2) == 3) {
		if ((laddr = inet_addr(str)) == -1) {
			lprint("Error: Bad address: %s\r\n", buff);
			return CFG_ERROR;
		}
	} else if (sscanf(buff, "%d%*[to \t]%256s", &port, str2) == 2) {
		if (inso)
		   laddr = inso->so_laddr.s_addr;
		else
		   laddr = inet_addr(CTL_LOCAL);
	} else if (sscanf(buff, "%256[^:]:%256s", str, str2) == 2) {
		if ((laddr = inet_addr(str)) == -1) {
			lprint("Error: Bad address: %s\r\n", buff);
			return CFG_ERROR;
		}
	} else if (sscanf(buff, "%256s", str2) == 1) {
		if (inso)
		   laddr = inso->so_laddr.s_addr;
		else
		   laddr = inet_addr(CTL_LOCAL);
	} else {
		return CFG_BADARGS;
	}
	
	lport = get_port(str2, proto_tcp);
	if (lport < 0)
	   return CFG_ERROR;
	
	/* Do the redirection */
	
	if (proto_tcp) {
		so = solisten(htons(port), laddr, htons(lport), once_time);
		
		if (so)
		   lprint("Redirecting TCP port %d to %s:%d\r\n",
				   ntohs(so->so_fport), inet_ntoa(so->so_laddr), lport);
		else
		   lprint("Redirection failed: %s\r\n", strerror(errno));
	} else {
		so = udp_listen(htons(port), laddr, htons(lport), once_time);
		
		if (so)
		   lprint("Redirecting UDP port %d to %s:%d\r\n",
				   ntohs(so->so_fport), inet_ntoa(so->so_laddr), lport);
		else
		   lprint("Redirection failed: %s\r\n", strerror(errno));
	}
	
	return CFG_OK;
}

#ifndef FULL_BOLT
int
cfg_baudrate(buff, inso)
	char *buff;
	struct socket *inso;
{
	int x;
	struct ttys *ttyp = ttys_unit[cfg_unit];
	
	if (!ttyp) {
		lprint("Error: Unit does not exist. Weird.\r\n");
		return CFG_ERROR;
	}
	
	x = atoi(buff);
	if (x < 300) {
		lprint("Error: baudrate too low\r\n");
		return CFG_ERROR;
	}
	ttyp->baud = x;
	ttyp->bytesps = ttyp->baud / 10; /* XXX */
	lprint("Setting baudrate to %d\r\n", ttyp->baud);
	
	return CFG_OK;
}
#endif

int
cfg_wait(buff, inso)
	char *buff;
	struct socket *inso;
{
	if (buff) {
		int x = atoi(buff);
		if (x < 0) {
			lprint("Error: wait value must be non-negative\r\n");
			return CFG_ERROR;
		}
		if (x > 24*60) {
			lprint("Error: wait value too large (one day max)\r\n");
			return CFG_ERROR;
		}
		detach_wait = x * 60 * 1000;
	}

	lprint("Wait time is %d minutes\r\n", detach_wait/1000/60);
	
	return CFG_OK;
}

int
cfg_sp_addr(buff, inso)
	char *buff;
	struct socket *inso;
{
	struct in_addr tmp_addr;
	
	if (!inet_aton(buff, &tmp_addr)) {
		lprint("Error: Bad special address: %s\r\n", buff);
		return CFG_ERROR;
	}
	special_addr = tmp_addr;
	lprint("Setting special address to %s\r\n", buff);
	
	return CFG_OK;
}


int
cfg_ctl_addr(buff, inso)
	char *buff;
	struct socket *inso;
{
	struct in_addr tmp_addr;
	
	if (!inet_aton(buff, &tmp_addr)) {
		lprint("Error: Bad control address: %s\r\n", buff);
		return CFG_ERROR;
	}
	
	ctl_addr = tmp_addr;
	lprint("Setting control address to %s\r\n", buff);
	
	return CFG_OK;
}

int
cfg_compress(buff, inso)
	char *buff;
	struct socket *inso;
{
	if_comp &= ~(IF_AUTOCOMP|IF_NOCOMPRESS);
	if_comp |= IF_COMPRESS;
	
	lprint("Setting VJ compression\r\n");
	
	return CFG_OK;
}
	
int
cfg_host_addr(buff, inso)
	char *buff;
	struct socket *inso;
{
	struct in_addr tmp_addr;
	
	if (!inet_aton(buff, &tmp_addr)) {
		lprint("Error: Bad host address: %s\r\n", buff);
		return CFG_ERROR;
	}
	our_addr = tmp_addr;
	lprint("Setting host address to %s\r\n", buff);
	
	return CFG_OK;
}


int
cfg_add_exec(buff, inso)
	char *buff;
	struct socket *inso;
{
	char str[256];
	char str2[256];
	char str3[256];
	int x;
	u_int32_t laddr;
	
	if (sscanf(buff, "%256[^:]:%256[^:]:%256s", str, str2, str3) == 3) {
		/* XXX should check if address == special address */
		x = get_port(str3, 1);
		if (x < 0)
		   return CFG_ERROR;
		if (x > 65535) {
			lprint("Error: Port out of range: %d\r\n", x);
			return CFG_ERROR;
		} else if ((laddr = inet_addr(str2)) == -1) {
			lprint("Error: Invalid address: %s\r\n", str2);
			return CFG_ERROR;
		} else if (add_exec(&exec_list, 0, str, (ntohl(laddr) & 0xff), htons(x)) < 0) {
			lprint("Error: Port already used: %s\r\n", buff);
			return CFG_ERROR;
		} else
			lprint("Adding execution of %s to address %s, port %d\r\n", str, str2, x);
	} else if (sscanf(buff, "%256[^:]:%256s", str, str3) == 2) {
		x = get_port(str3, 1);
		if (x < 0)
		   return CFG_ERROR;
		if (x > 65535) {
			lprint("Error: Port out of range: %d\r\n", x);
			return CFG_ERROR;
		} else if (add_exec(&exec_list, 0, str, CTL_EXEC, htons(x)) < 0) {
			lprint("Error: Port already used: %s\r\n", buff);
			return CFG_ERROR;
		} else
			lprint("Adding execution of %s to port %d\r\n", str, x);
	} else
		return CFG_BADARGS;
	
	return CFG_OK;
}


int
cfg_add_ptyexec(buff, inso)
	char *buff;
	struct socket *inso;
{
	char str[256];
	char str2[256];
	int x;
	u_int32_t laddr;
	
	
	if (sscanf(buff, "%256[^:]:%256[^:]:%d", str, str2, &x) == 3) {
		/* XXX should check if address == special address */
		if (x < 0 || x > 65535) {
			lprint("Error: Port out of range: %d\r\n", x);
			return CFG_ERROR;
		} else if ((laddr = inet_addr(str2)) == -1) {
			lprint("Error: Invalid address: %s\r\n", str2);
			return CFG_ERROR;
		} else if (add_exec(&exec_list, 1, str, (ntohl(laddr) & 0xff), htons(x)) < 0) {
			lprint("Error: Port already used: %s\r\n", buff);
			return CFG_ERROR;
		} else
			lprint("Adding %s to address %s, port %d\r\n", str, str2, x);
	} else if (sscanf(buff, "%256[^:]:%d", str, &x) == 2) {
		if (x < 0 || x > 65535) {
			lprint("Error: Port out of range: %d\r\n", x);
			return CFG_ERROR;
		} else if (add_exec(&exec_list, 1, str, CTL_EXEC, htons(x)) < 0) {
			lprint("Error: Port already used.\r\n");
			return CFG_ERROR;
		} else
			lprint("Adding %s to port %d\r\n", str, x);
	} else
		return CFG_BADARGS;
	
	return CFG_OK;
}


int
cfg_shell(buff, inso)
	char *buff;
	struct socket *inso;
{
	char str[256];
	
	if (exec_shell)
	   free(exec_shell);
	sscanf(buff, "%256s", str);
	exec_shell = (char *)strdup(str);
	
	return CFG_OK;
}


int
cfg_debug(buff, inso)
	char *buff;
	struct socket *inso;
{
	int x;

	if (!buff)
		x = DEBUG_DEFAULT;
	else {
		if ((x = atoi(buff)) == 0)
		   x = DEBUG_DEFAULT;
	}

	debug_init("slirp_debug", x);

	return CFG_OK;
}

int
cfg_logstart(buff, inso)
	char *buff;
	struct socket *inso;
{
	char buff1[256];
	char *bptr;
	
	if (!buff) {
		buff1[0] = 0;
		if ((bptr = (char *)getenv("HOME")) != NULL)
		   strncpy2(buff1, bptr, sizeof(buff1));
		strncat(buff1, "/.slirp_start", sizeof(buff1));
		lfd = fopen(buff1, "w");
		bptr = buff1;
	} else {
		lfd = fopen(buff, "w");
		bptr = buff;
	}
	
	if (!lfd) {
		lprint("Error: could not open logstart file: %s\r\n", strerror(errno));
		return CFG_ERROR;
	}
	lprint("Log started to %s\r\n", bptr);
	
	return CFG_OK;
}

int
cfg_logstats(buff, inso)
	char *buff;
	struct socket *inso;
{
	dostats = 1;
	
	lprint("Logging statistics\r\n");
	
	return CFG_OK;
}

int
cfg_config(buff, inso)
	char *buff;
	struct socket *inso;
{
	config(buff, cfg_unit);
	
	return CFG_OK;
}

int
cfg_help(buff, inso)
	char *buff;
	struct socket *inso;
{
	int i = 0;
	int str_len;
	int count = 0;
	char str[256];
	char *str2;
	char *sptr;
	
	if (!buff) {
		lprint("Valid commands:\r\n");
		while (cfg[i].command) {
			if (count >= 2) {
				sprintf(str, "\r\n");
				count = 0;
			} else {
				count++;
				sptr = str;
				str_len = strlen(cfg[i].command);
				str_len = 20 - str_len;
				while (str_len-- >= 0)
				   *sptr++ = ' ';
				*sptr = 0;
			}
			lprint("%s%s", cfg[i].command, str);
			i++;
		}
		if (count != 0)
		   lprint("\r\n");
		lprint("For more help type \"help COMMAND\" where command is either\r\n");
		lprint("one of the above commands or a portion of a command.\r\n");
	} else {
		str_len = strlen(buff);
		while (cfg[i].command) {
			if (!strncmp(cfg[i].command, buff, str_len) ||
			    (cfg[i].command_line && !strncmp(cfg[i].command_line, buff, str_len))) {
				/* Found a match, print the help */
				count++;
				if (cfg[i].command_line)
				   snprintf(str, sizeof(str), "Command-line: %s\r\n", cfg[i].command_line);
				else
				   str[0] = 0;
				if (cfg[i].type == CFG_TELNET)
				   str2 = "telnet";
				else if (cfg[i].type == CFG_CMD_FILE)
				   str2 = "command-line, config-file";
				else if (cfg[i].type == (CFG_ANY))
				   str2 = "command-line, config-file, telnet";
				else
				   str2 = "[none]";
				lprint(
			"Command: \"%s\"\r\nUsage: %s %s\r\n%sAvailable: %s\r\n        %s\r\n\r\n",
			 cfg[i].command, cfg[i].command, cfg[i].usage_args, str, str2, cfg[i].help);
			}
			i++;
		}
		lprint("%d match(es) found\r\n", count);
	}

	/* If it was called from the command-line, exit */
	if (!inso)
	   slirp_exit(0);

	return CFG_OK;
}

int
cfg_stats(buff, inso)
	char *buff;
	struct socket *inso;
{
	if (!strncmp(buff, "ip", 2))
	   ipstats();
	else if (!strncmp(buff, "socket", 6))
	   sockstats();
	else if (!strncmp(buff, "tcp", 3))
	   tcpstats();
	else if (!strncmp(buff, "udp", 3))
	   udpstats();
	else if (!strncmp(buff, "icmp", 4))
	   icmpstats();
	else if (!strncmp(buff, "mbuf", 4))
	   mbufstats();
	else if (!strncmp(buff, "vj", 2))
	   vjstats();
	else if (!strncmp(buff, "alltty", 6))
	   allttystats();
	else if (!strncmp(buff, "tty", 3))
	   ttystats(ttys_unit[cfg_unit]);
	else
	   return CFG_BADARGS;
	
	return CFG_OK;
}

int
cfg_echo(buff, inso)
	char *buff;
	struct socket *inso;
{
	if (!buff) {
		lprint("Echo is %s\r\n", do_echo?"on":"off");
	} else {
		if (strncmp(buff, "on", 2) == 0) {
			do_echo = 1;
			lprint("Echo is on.\r\n");
		} else if (strncmp(buff, "off", 3) == 0) {
			do_echo = 0;
			lprint("Echo is off\r\n");
		} else
			return CFG_BADARGS;
	}
	
	return CFG_OK;
}

int
cfg_kill_close(x, type)
	int x, type;
{
	struct socket *so;
	
	for (so = tcb.so_next; so != &tcb; so = so->so_next) {
		if (so->s == x) {
			/* Found it */
			if (type == 1) {
				tcp_close(sototcpcb(so));
				lprint(
						"Session removed.\r\n");
			} else {
				tcp_sockclosed(sototcpcb(so));
				shutdown(so->s, 0); /* XXX */
				shutdown(so->s, 1); /* XXX */
				so->so_state = SS_NOFDREF; /* XXX */
				lprint("Session closed.\r\n");
			}
			return CFG_OK;
		}
	}
	
	/*
	 * Not TCP, maybe UDP
	 */
	for (so = udb.so_next; so != &tcb; so = so->so_next) {
		if (so->s == x) {
			udp_detach(so);
			lprint("Session closed.\r\n");
			return CFG_OK;
		}
	}
				
	/*
	 * Nup, cant find it
	 */
	lprint(" Error: session not found.\r\n");
	
	return CFG_ERROR;
}

int cfg_quitting;

int
cfg_quit(buff, inso)
	char *buff;
	struct socket *inso;
{
	lprint("Goodbye\r\n");
	tcp_sockclosed(sototcpcb(inso));
	cfg_quitting = 1;

	return CFG_OK;
}


int
cfg_pass(buff, inso)
	char *buff;
	struct socket *inso;
{
	char *ptr = buff;

	if (ctl_password)
	   free(ctl_password);
	while (*ptr) {
		if (*ptr == '\n' || *ptr == '\r')
		   *ptr = 0;
		else
		   ptr++;
	}
	ctl_password = strdup(buff);

	return CFG_OK;
}

int
cfg_tty(buff, inso)
    char *buff;
    struct socket *inso;
{
    /* TTY actually set up earlier prior to main options processing
       (Only usable on command line)
    */
	return CFG_OK;
}

int
cfg_nozeros(buff, inso)
    char *buff;
    struct socket *inso;
{
    /* Disable special zero processing
    */
    nozeros++;
	return CFG_OK;
}


int
cfg_kill(buff, inso)
	char *buff;
	struct socket *inso;
{
	cfg_kill_close(atoi(buff), 1);

	return CFG_OK;
}

int
cfg_close(buff, inso)
	char *buff;
	struct socket *inso;
{
	cfg_kill_close(atoi(buff), 0);

	return CFG_OK;
}

int
cfg_exec(buff, inso)
	char *buff;
	struct socket *inso;
{
	fork_exec(inso, buff, 0);
	soisfconnected(inso);
	inso->so_emu = 0;

	return CFG_OK;
}

int
cfg_ptyexec(buff, inso)
	char *buff;
	struct socket *inso;
{
	fork_exec(inso, buff, 1);
	soisfconnected(inso);
	inso->so_emu = 0;

	return CFG_OK;
}

int
cfg_add_emu(buff, inso)
	char *buff;
	struct socket *inso;
{
	add_emu(buff);

	return CFG_OK;
}

int
cfg_socket(buff, inso)
	char *buff;
	struct socket *inso;
{
	struct sockaddr_in addr;
	char pwd[256];
	int s, port;

	if (!buff) {
		/* Want unix domain socket */
#ifndef NO_UNIX_SOCKETS
		struct sockaddr_un sock_un;

		if (slirp_socket >= 0) {
			/* Close the old socket */
			close(slirp_socket);
			slirp_socket = -1;
		}

		if (slirp_socket_passwd) {
			free(slirp_socket_passwd);
			slirp_socket_passwd = 0;
		}

		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0) {
			lprint("Error: socket() failed\r\n");
			return CFG_ERROR;
		}

		/* Remove the old socket */
		(void) unlink(socket_path);

		/* Create a new one */
		sock_un.sun_family = AF_UNIX;
		strncpy2(sock_un.sun_path, socket_path, sizeof(sock_un.sun_path));
		if ((bind(s, (struct sockaddr *)&sock_un,
			  sizeof(sock_un.sun_family) + sizeof(sock_un.sun_path)) < 0) ||
		    (listen(s, 1) < 0)) {
			close(s);
			lprint("Error: %s: %s\r\n", socket_path, strerror(errno));

			return CFG_ERROR;
		}

		slirp_socket = s;

		return CFG_OK;
#else
		lprint("Sorry, your system does not support unix-domain sockets.\r\n");

		return CFG_OK;
#endif
	} else {
		/* Want internet domain socket */
		if (slirp_socket >= 0) {
			/* Close the old socket */
			close(slirp_socket);
			slirp_socket = -1;
		}

		if (sscanf(buff, "%d,%s", &port, pwd) != 2) {
			lprint("Error: bad arguments to \"socket\"\r\n");
			return CFG_ERROR;
		}

		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) {
			lprint("Error: socket() failed: %s\r\n", strerror(errno));
			close(s);
			return CFG_ERROR;
		}

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
			lprint("Error: bind() failed: %s\r\n", strerror(errno));
			close(s);
			return CFG_ERROR;
		}

		listen(s, 1);

		slirp_socket = s;

		if (slirp_socket_passwd) {
			/* Free old password */
			free(slirp_socket_passwd);
		}
		slirp_socket_passwd = strdup(pwd);

		return CFG_OK;
	}
}


int
cfg_dns(buff, inso)
	char *buff;
	struct socket *inso;
{
	struct in_addr tmp_addr;

	if (!inet_aton(buff, &tmp_addr)) {
		lprint("Error: Bad IP\r\n");
		return CFG_ERROR;
	}

    if(dns_addr.s_addr) {
        dns2_addr = tmp_addr;
    	lprint("Setting DNS2 to %s\r\n", buff);
    }
    else {
    	dns_addr = tmp_addr;
	    lprint("Setting DNS to %s\r\n", buff);
    }

	return CFG_OK;
}

int
cfg_keepalive(buff, inso)
	char *buff;
	struct socket *inso;
{
	int tmp;

	if (buff) {
		tmp = atoi(buff);
		if (tmp < 5*PR_SLOWHZ || tmp > tcp_keepidle) {
			lprint("Error: TCP keepalive interval must be between 5 and %d\r\n", tcp_keepidle);
			return CFG_ERROR;
		}
		tcp_keepintvl = tmp*PR_SLOWHZ;
	}
	so_options = 1;

	lprint("Setting keepalive to %d seconds\r\n", tcp_keepintvl/PR_SLOWHZ);

	return CFG_OK;
}

int
cfg_version(buff, inso)
	char *buff;
	struct socket *inso;
{
	lprint("Slirp v%s (%s)\r\n", SLIRP_VERSION, SLIRP_STATUS);

	return CFG_OK;
}

int
cfg_towrite_max(buff, inso)
	char *buff;
	struct socket *inso;
{
	int tmp;

	tmp = atoi(buff);

	if (tmp < 0) {
		lprint("Error: towrite_max must be positive\r\n");
		return CFG_ERROR;
	}

	towrite_max = tmp;
	lprint("Setting towrite_max to %d\r\n", towrite_max);

	return CFG_OK;
}


#ifdef USE_PPP

int
cfg_ppp_exit(buff, inso)
	char *buff;
	struct socket *inso;
{
	ppp_exit = 1;

	lprint("Slirp will exit when PPP goes down\r\n");

	return CFG_OK;
}

void
setipdefault(unit)
	int unit;
{
	struct hostent *hp;
	u_int32_t local;
	ipcp_options *wo = &ipcp_wantoptions[unit];

	/*
	 * If local IP address already given, don't bother.
	 */
	if (wo->ouraddr != 0 || disable_defaultip)
	   return;

	/*
	 * Look up our hostname (possibly with domain name appended)
	 * and take the first IP address as our local IP address.
	 * If there isn't an IP address for our hostname, too bad.
	 */
	wo->accept_local = 1;       /* don't insist on this default value */
	if ((hp = gethostbyname(hostname)) == NULL)
	   return;
	local = *(u_int32_t *)hp->h_addr;
	if (local != 0 && !bad_ip_adrs(local))
	   wo->ouraddr = local;

	return;
}

/*
 * Read a word from a file.
 * Words are delimited by white-space or by quotes (").
 * Quotes, white-space and \ may be escaped with \.
 * \<newline> is ignored.
 */
int
getword(f, word, newlinep, filename)
    FILE *f;
    char *word;
    int *newlinep;
    char *filename;
{
	int c, len, escape;
	int quoted;
	
	*newlinep = 0;
	len = 0;
	escape = 0;
	quoted = 0;
	
	/*
	 * First skip white-space and comments
	 */
	while ((c = getc(f)) != EOF) {
		if (c == '\\') {
			/*
			 * \<newline> is ignored; \ followed by anything else
			 * starts a word.
			 */
			if ((c = getc(f)) == '\n')
			   continue;
			word[len++] = '\\';
			escape = 1;
			break;
		}
		if (c == '\n')
		   *newlinep = 1;      /* next word starts a line */
		else if (c == '#') {
			/* comment - ignore until EOF or \r\n */
			while ((c = getc(f)) != EOF && c != '\n')
			   ;
			if (c == EOF)
			   break;
			*newlinep = 1;
		} else if (!isspace(c))
		   break;
	}
	
	/*
	 * End of file or error - fail
	 */
	if (c == EOF) {
		if (ferror(f)) {
			perror(filename);
			die(1);
		}
		return 0;
	}
	
	for (;;) {
		/*
		 * Is this character escaped by \ ?
		 */
		if (escape) {
			if (c == '\n')
			   --len;                  /* ignore \<newline> */
			else if (c == '"' || isspace(c) || c == '\\')
			   word[len-1] = c;        /* put special char in word */
			else {
				if (len < MAXWORDLEN-1)
				   word[len] = c;
				++len;
			}
			escape = 0;
		} else if (c == '"') {
			quoted = !quoted;
		} else if (!quoted && (isspace(c) || c == '#')) {
			ungetc(c, f);
			break;
		} else {
			if (len < MAXWORDLEN-1)
			   word[len] = c;
			++len;
			if (c == '\\')
			   escape = 1;
		}
		if ((c = getc(f)) == EOF)
		   break;
	}
	
	if (ferror(f)) {
		perror(filename);
		die(1);
	}
	
	if (len >= MAXWORDLEN) {
		word[MAXWORDLEN-1] = 0;
		lprint("Warning: word in file %s too long (%.20s...)\r\n",
			filename, word);
	} else
	   word[len] = 0;
	
	return 1;
}

u_int32_t
GetMask(addr)
    u_int32_t addr;
{
	return(netmask);
}


/*
 * number_option - parse a numeric parameter for an option
 */
u_int
number_option(str, valp, base)
    char *str;
    u_int32_t *valp;
    int base;
{
	char *bptr;
	
	*valp = strtoul(str, &bptr, base);
	if (bptr == str) {
		lprint("invalid number: %s\r\n", str);
		return CFG_ERROR;
	}
	return CFG_OK;
}


/*
 * int_option - like number_option, but valp is int *,
 * the base is assumed to be 0, and *valp is not changed
 * if there is an error.
 */
u_int
int_option(str, valp)
    char *str;
    int *valp;
{
	u_int32_t v;
	
	if (number_option(str, &v, 0) == CFG_ERROR)
	   return CFG_ERROR;
	*valp = (u_int) v;
	return CFG_OK;
}

#endif

int
cfg_ppp(buff, inso)
	char *buff;
	struct socket *inso;
{
#ifdef USE_PPP
	struct ttys *ttyp = ttys_unit[cfg_unit];
	
	if (!ttyp) {
		lprint("Error: Unit does not exists.  Weird.\r\n");
		return CFG_ERROR;
	}
	ppp_init(ttyp);
	
	return CFG_OK;
#else
	lprint("Error: PPP not compiled into this slirp executable\r\n");
	
	return CFG_OK;
#endif
}

#ifdef USE_PPP

/*
 * The following procedures execute commands.
 */

/*
 * setdebug - Set debug (command line argument).
 */
int
setdebug(buff, inso)
	char *buff;
	struct socket *inso;
{
	if (logfile)
	   fclose(logfile);
	logfile = fopen("slirp_pppdebug", "w");
	if (!logfile) {
		lprint("Error: can't open logfile\r\n");
		return CFG_ERROR;
	}
	debug = 1;
	
	return CFG_OK;
}

/*
 * noopt - Disable all options.
 */
int
noopt(buff, inso)
	char *buff;
	struct socket *inso;
{
	BZERO((char *) &lcp_wantoptions[cfg_unit], sizeof (struct lcp_options));
	BZERO((char *) &lcp_allowoptions[cfg_unit], sizeof (struct lcp_options));
	BZERO((char *) &ipcp_wantoptions[cfg_unit], sizeof (struct ipcp_options));
	BZERO((char *) &ipcp_allowoptions[cfg_unit], sizeof (struct ipcp_options));
	
	return CFG_OK;
}

/*
 * noaccomp - Disable Address/Control field compression negotiation.
 */
int
noaccomp(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_accompression = 0;
	lcp_allowoptions[cfg_unit].neg_accompression = 0;
	
	return CFG_OK;
}


/*
 * noasyncmap - Disable async map negotiation.
 */
int
noasyncmap(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_asyncmap = 0;
	lcp_allowoptions[cfg_unit].neg_asyncmap = 0;
	
	return CFG_OK;
}


/*
 * noipaddr - Disable IP address negotiation.
 */
int
noipaddr(buff, inso)
        char *buff;
        struct socket *inso;
{
	ipcp_wantoptions[cfg_unit].neg_addr = 0;
	ipcp_allowoptions[cfg_unit].neg_addr = 0;
	
	return CFG_OK;
}


/*
 * nomagicnumber - Disable magic number negotiation.
 */
int
nomagicnumber(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_magicnumber = 0;
	lcp_allowoptions[cfg_unit].neg_magicnumber = 0;

	return CFG_OK;
}


/*
 * nomru - Disable mru negotiation.
 */
int
nomru(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_mru = 0;
	lcp_allowoptions[cfg_unit].neg_mru = 0;
	
	return CFG_OK;
}

#endif

/*
 * setmru - Set MRU for negotiation.
 */
int
setmru(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	long mru;
	
	/* PPP */
	mru = atoi(opt_arg);
#ifdef USE_PPP
	lcp_wantoptions[cfg_unit].mru = mru;
	lcp_wantoptions[cfg_unit].neg_mru = 1;
#endif	
	/* SLIP */
	if_mru = mru;
	
	return CFG_OK;
}


/*
 * setmtu - Set the largest MTU we'll use.
 */
int
setmtu(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	long mtu;
	
	/* PPP */
	mtu = atoi(opt_arg);
	if (mtu < MIN_MRU || mtu > MAX_MRU) {
		lprint("mtu option value of %ld is too %s\r\n", mtu,
		       (mtu < MIN_MRU? "small": "large"));
		return CFG_ERROR;;
	}
#ifdef USE_PPP
	lcp_allowoptions[cfg_unit].mru = mtu;
#endif	
	/* SLIP XXXXX */
	if_mtu = mtu;
	
	return CFG_OK;
}

#ifdef USE_PPP

/*
 * nopcomp - Disable Protocol field compression negotiation.
 */
int
nopcomp(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_pcompression = 0;
	lcp_allowoptions[cfg_unit].neg_pcompression = 0;
	
	return CFG_OK;
}

/*
 * setsilent - Set silent mode (don't start sending LCP configure-requests
 * until we get one from the peer).
 */
int
setinitopt(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].silent = 0;
	
	return CFG_OK;
}


/*
 * nopap - Disable PAP authentication with peer.
 */
int
nopap(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_allowoptions[cfg_unit].neg_upap = 0;
	
	return CFG_OK;
}


/*
 * reqpap - Require PAP authentication from peer.
 */
int
reqpap(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_upap = 1;
	auth_required = 1;
	
	return CFG_OK;
}


/*
 * setupapfile - specifies UPAP info for authenticating with peer.
 */
int
setupapfile(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	FILE * ufile;
	int l;
	
	lcp_allowoptions[cfg_unit].neg_upap = 1;
	
	/* open user info file */
	if ((ufile = fopen(opt_arg, "r")) == NULL) {
		lprint("unable to open user login data file %s\r\n", opt_arg);
		return CFG_ERROR;
	}
	check_access(ufile, opt_arg);
	
	/* get username */
	if (fgets(user, MAXNAMELEN - 1, ufile) == NULL
	    || fgets(passwd, MAXSECRETLEN - 1, ufile) == NULL){
		lprint("Unable to read user login data file %s.\r\n", opt_arg);
		return CFG_ERROR;
	}
	fclose(ufile);
	
	/* get rid of newlines */
	l = strlen(user);
	if (l > 0 && user[l-1] == '\n')
	   user[l-1] = 0;
	l = strlen(passwd);
	if (l > 0 && passwd[l-1] == '\n')
	   passwd[l-1] = 0;
	
	return CFG_OK;
}


/*
 * nochap - Disable CHAP authentication with peer.
 */
int
nochap(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_allowoptions[cfg_unit].neg_chap = 0;
	
	return CFG_OK;
}


/*
 * reqchap - Require CHAP authentication from peer.
 */
int
reqchap(buff, inso)
        char *buff;
        struct socket *inso;
{
	lcp_wantoptions[cfg_unit].neg_chap = 1;
	auth_required = 1;
	
	return CFG_OK;
}


/*
 * setnovj - disable vj compression
 */
int
setnovj(buff, inso)
        char *buff;
        struct socket *inso;
{
	if_comp &= ~(IF_AUTOCOMP|IF_COMPRESS);
	if_comp |= IF_NOCOMPRESS;
	ipcp_wantoptions[cfg_unit].neg_vj = 0;
	ipcp_allowoptions[cfg_unit].neg_vj = 0;
	
	return CFG_OK;
}


/*
 * setnovjccomp - disable VJ connection-ID compression
 */
int
setnovjccomp(buff, inso)
        char *buff;
        struct socket *inso;
{
	ipcp_wantoptions[cfg_unit].cflag = 0;
	ipcp_allowoptions[cfg_unit].cflag = 0;
	
	return CFG_OK;
}


/*
 * setvjslots - set maximum number of connection slots for VJ compression
 */
int
setvjslots(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	int value;
	
	if (int_option(opt_arg, &value) == CFG_ERROR)
	   return CFG_ERROR;
	if (value < 2 || value > 16) {
		lprint("pppd: vj-max-slots value must be between 2 and 16\r\n");
		return CFG_ERROR;
	}
	ipcp_wantoptions[cfg_unit].maxslotindex =
        ipcp_allowoptions[cfg_unit].maxslotindex = value - 1;
	
	return CFG_OK;
}


/*
 * setdomain - Set domain name to append to hostname 
 */
int
setdomain(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	strncat(hostname, opt_arg, MAXNAMELEN - strlen(hostname));
	hostname[MAXNAMELEN-1] = 0;
	
	return CFG_OK;
}


/*
 * setasyncmap - add bits to asyncmap (what we request peer to escape).
 */
int
setasyncmap(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	u_int32_t asyncmap;
	
	if (number_option(opt_arg, &asyncmap, 16) == CFG_ERROR)
	   return CFG_ERROR;
	lcp_wantoptions[cfg_unit].asyncmap |= asyncmap;
	lcp_wantoptions[cfg_unit].neg_asyncmap = 1;
	
	return CFG_OK;
}


/*
 * setescape - add chars to the set we escape on transmission.
 */
int
setescape(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	int n, n2, ret, num = 0;
	char *p, *endp;
	
	p = opt_arg;
	ret = CFG_OK;
	lprint("Escaping: ");
	while (*p) {
		n = strtoul(p, &endp, 16);
		if (p == endp) {
			lprint("\r\nError: invalid hex number: %s\r\n", p);
			return CFG_ERROR;
		}
		p = endp;
		if (*p == '-') {
			p++;
			n2 = strtoul(p, &endp, 16);
			if (p == endp) {
				lprint("\r\nError: invalid hex number: %s\r\n", p);
				return CFG_ERROR;
			}
			p = endp;
			if (n2 < n || n2 > 0xff) {
				lprint("\r\nError: bad second number in range\r\n");
				return CFG_ERROR;
			}
		} else
			n2 = n;
		
		while (n <= n2) {
			if (n < 0 || (0x20 <= n && n <= 0x3F) || n == 0x5E || n > 0xFF) {
				lprint("\r\nError: can't escape character 0x%x\r\n", n);
				ret = CFG_ERROR;
			} else {
				if (num)
				   lprint(", ");
				lprint("0x%x", n);
				num++;
				xmit_accm[cfg_unit][n >> 5] |= 1 << (n & 0x1F);
			}
			n++;
		}
		
		while (*p == ',' || *p == ' ' || *p == '\n' || *p == '\r')
		   ++p;
	}
	lprint("\r\n");
	
	if (!num)
	   return CFG_BADARGS;
	else
	   return ret;
}


/*
 * setipcpaccl - accept peer's idea of our address
 */
int
setipcpaccl(buff, inso)
        char *buff;
        struct socket *inso;
{
	ipcp_wantoptions[cfg_unit].accept_local = 1;
	
	return CFG_OK;
}


/*
 * setipcpaccr - accept peer's idea of its address
 */
int
setipcpaccr(buff, inso)
        char *buff;
        struct socket *inso;
{
	ipcp_wantoptions[cfg_unit].accept_remote = 1;
	
	return CFG_OK;
}

int
setusehostname(buff, inso)
        char *buff;
        struct socket *inso;
{
	usehostname = 1;
	
	return CFG_OK;
}

int
setname(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	if (our_name[cfg_unit] == 0) {
		strncpy(our_name, opt_arg, MAXNAMELEN);
		our_name[MAXNAMELEN-1] = 0;
	}
	
	return CFG_OK;
}

int
set_user(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	strncpy(user, opt_arg, MAXNAMELEN);
	user[MAXNAMELEN-1] = 0;
	
	return CFG_OK;
}

int
setremote(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	strncpy(remote_name, opt_arg, MAXNAMELEN);
	remote_name[MAXNAMELEN-1] = 0;
	
	return CFG_OK;
}

int
setauth(buff, inso)
        char *buff;
        struct socket *inso;
{
	auth_required = 1;
	
	return CFG_OK;
}

int
setproxyarp(buff, inso)
        char *buff;
        struct socket *inso;
{
	ipcp_wantoptions[cfg_unit].proxy_arp = 1;
	
	return CFG_OK;
}

int
setdologin(buff, inso)
        char *buff;
        struct socket *inso;
{
	uselogin = 1;
	
	return CFG_OK;
}

/*
 * Functions to set the echo interval for modem-less monitors
 */

int
setlcpechointv(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_echo_interval);
}

int
setlcpechofails(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_echo_fails);
}

/*
 * Functions to set timeouts, max transmits, etc.
 */
int
setlcptimeout(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_fsm[cfg_unit].timeouttime);
}

int
setlcpterm(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_fsm[cfg_unit].maxtermtransmits);
}

int
setlcpconf(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_fsm[cfg_unit].maxconfreqtransmits);
}

int
setlcpfails(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_fsm[cfg_unit].maxnakloops);
}

int
setipcptimeout(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &ipcp_fsm[cfg_unit].timeouttime);
}

int
setipcpterm(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &ipcp_fsm[cfg_unit].maxtermtransmits);
}

int
setipcpconf(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &ipcp_fsm[cfg_unit].maxconfreqtransmits);
}

int
setipcpfails(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &lcp_fsm[cfg_unit].maxnakloops);
}

int
setpaptimeout(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &upap[cfg_unit].us_timeouttime);
}

int
setpapreqs(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &upap[cfg_unit].us_maxtransmits);
}

int
setchaptimeout(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &chap[cfg_unit].timeouttime);
}

int
setchapchal(opt_arg, inso)
	char *opt_arg;
        struct socket *inso;
{
	return int_option(opt_arg, &chap[cfg_unit].max_transmits);
}

int
setchapintv(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	return int_option(opt_arg, &chap[cfg_unit].chal_interval);
}

int
setpapreqtime(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	return int_option(opt_arg, &upap[cfg_unit].us_reqtimeout);
}

int
setbsdcomp(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	int rbits, abits;
	char *str, *endp;
	
	str = opt_arg;
	abits = rbits = strtol(str, &endp, 0);
	if (endp != str && *endp == ',') {
		str = endp + 1;
		abits = strtol(str, &endp, 0);
	}
	if ((*endp != 0 && *endp != '\n' && *endp != '\r') || endp == str) {
		lprint("Error: invalid argument format for bsdcomp option\n");
		return CFG_ERROR;
	}
	if ((rbits != 0 && (rbits < BSD_MIN_BITS || rbits > BSD_MAX_BITS))
	    || (abits != 0 && (abits < BSD_MIN_BITS || abits > BSD_MAX_BITS))) {
		lprint("Error: bsdcomp option values must be 0 or %d .. %d\n",
		       BSD_MIN_BITS, BSD_MAX_BITS);
		return CFG_ERROR;
	}
	if (rbits > 0) {
		ccp_wantoptions[cfg_unit].bsd_compress = 1;
		ccp_wantoptions[cfg_unit].bsd_bits = rbits;
	} else
		ccp_wantoptions[cfg_unit].bsd_compress = 0;
	if (abits > 0) {
		ccp_allowoptions[cfg_unit].bsd_compress = 1;
		ccp_allowoptions[cfg_unit].bsd_bits = abits;
	} else
		ccp_allowoptions[cfg_unit].bsd_compress = 0;
	
	return CFG_OK;
}

int
setnobsdcomp(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	ccp_wantoptions[cfg_unit].bsd_compress = 0;
	ccp_allowoptions[cfg_unit].bsd_compress = 0;
	
	return CFG_OK;
}

int
setpapcrypt(opt_arg, inso)
	char *opt_arg;
	struct socket *inso;
{
	cryptpap = 1;
	
	return CFG_OK;
}

#endif

struct cfgtab cfg[] = {
	  { "redir X", 0, cfg_redir_x, CFG_ANY, 0,
		  "[start RDISP] [ADDR][:DISPLAY[.SCREEN]]",
		  "redirect a port for X" },
	  { "show X", 0, show_x, CFG_TELNET, 0,
		  "",
		  "show a previous redirection" },
	  { "redir", 0, cfg_redir, CFG_ANY, CFG_NEEDARG,
		  "[once|time] [udp|tcp] PORT [to] [ADDR:]LPORT",
		  "redirect a port" },
#ifndef FULL_BOLT
	  { "baudrate", "-b", cfg_baudrate, CFG_ANY, CFG_NEEDARG,
		  "BAUDRATE",
		  "change the baudrate" },
#endif
	  { "special addr", 0, cfg_sp_addr, CFG_ANY, CFG_NEEDARG,
		  "ADDR",
		  "set slirp's special address" },
	  { "control addr", 0, cfg_ctl_addr, CFG_ANY, CFG_NEEDARG,
		  "ADDR",
		  "set slirp's control address" },
	  { "compress", 0, cfg_compress, CFG_CMD_FILE, 0,
		  "",
		  "use VJ compression" },
	  { "host addr", 0, cfg_host_addr, CFG_ANY, CFG_NEEDARG,
		  "ADDR",
		  "set slirp's host address" },
	  { "add exec", 0, cfg_add_exec, CFG_ANY, CFG_NEEDARG,
		  "| ptyexec PROGRAM:[ADDRESS:]PORT",
		  "make slirp execute a program on connection to a specific host/port" },
	  { "add ptyexec", 0, cfg_add_ptyexec, CFG_ANY, CFG_NEEDARG,
		  "| exec PROGRAM:[ADDRESS:]PORT",
		  "make slirp execute a program on connection to a specific host/port" },
	  { "add emu", 0, cfg_add_emu, CFG_ANY, CFG_NEEDARG,
		  "ftp|irc|none[:lowdelay|throughput] [LPORT:]FPORT",
		  "add emulation to specific service/port" },
	  { "shell", 0, cfg_shell, CFG_CMD_FILE, CFG_NEEDARG,
		  "PATH_TO_SHELL",
		  "set your shell (same as add ptyexec PATH_TO_SHELL:23)" },
	  { "debug", "-d", cfg_debug, CFG_ANY, CFG_NEEDARG,
		  "LEVEL",
		  "start debugging to file slirp_debug" },
	  { "socket", "-s", cfg_socket, CFG_ANY, 0,
		  "[PORT,PASSWORD]",
		  "bind a socket and listen for other unit connections" },
	  { "log stats", "-S", cfg_logstats, CFG_CMD_FILE, 0,
		  "",
		  "log statistics to file slirp_stats upon exit" },
	  { "config", "-f", cfg_config, CFG_CMD_FILE, CFG_NEEDARG,
		  "FILE",
		  "read a configuration file" },
	  { "log start", 0, cfg_logstart, CFG_CMD_FILE, 0,
		  "",
		  "log startup info to ~/.slirp_start" },
	  { "dns", 0, cfg_dns, CFG_ANY, CFG_NEEDARG,
		  "ADDR",
		  "set dns address, for 10.0.2.3 as an alias for the real dns" },

	  { "help", 0, cfg_help, CFG_ANY, 0,
		  "[COMMAND|START_OF_COMMAND]",
		  "show help on given command" },
	  { "-h", 0, cfg_help, CFG_ANY, CFG_NEEDARG,
		  "[COMMAND|START_OF_COMMAND]",
		  "show help on given command" },
	  { "echo", 0, cfg_echo, CFG_TELNET, 0,
		  "[on|off]",
		  "set echo on or off, or show current state" },
	  { "kill", 0, cfg_kill, CFG_TELNET, CFG_NEEDARG,
		  "SOCKET",
		  "kill a socket" },
	  { "close", 0, cfg_close, CFG_TELNET, CFG_NEEDARG,
		  "SOCKET",
		  "close a socket" },
	  { "stats", 0, cfg_stats, CFG_TELNET, CFG_NEEDARG,
		  "ip|socket|tcp|udp|icmp|mbuf|tty|alltty|vj",
		  "show statistics" },
	  { "exec", 0, cfg_exec, CFG_TELNET, CFG_NEEDARG,
		  "PATH_TO_PROGRAM",
		  "execute a program" },
	  { "ptyexec", 0, cfg_ptyexec, CFG_TELNET, CFG_NEEDARG,
		  "PATH_TO_PROGRAM",
		  "execute a program in a pty" },
	  { "unit", 0, cfg_setunit, CFG_TELNET, CFG_NEEDARG,
		  "N",
		  "configure a different unit" },
	  { "wait", 0, cfg_wait, CFG_ANY, 0,
		  "[MINUTES]",
		  "set or show number of minutes slirp will linger after a disconnect" },
	  { "quit", 0, cfg_quit, CFG_TELNET, 0,
		  "",
		  "quit the command-line" },
	  { "password", 0, cfg_pass, CFG_CMD_FILE, CFG_NEEDARG,
		  "PASSWORD",
		  "make PASSWORD a password for telnet 10.0.2.0" },
	  { "keepalive", 0, cfg_keepalive, CFG_CMD_FILE, 0,
		  "[SECONDS]",
		  "make Slirp probe each TCP connection [every SECONDS seconds]" },
	  { "version", "-v", cfg_version, CFG_ANY, 0,
		  "",
		  "print Slirp's version" },
	  { "towrite_max", 0, cfg_towrite_max, CFG_ANY, CFG_NEEDARG,
		  "NUM",
		  "set the maximum towrite per tty (see slirp.doc for details)" },
      { "tty", 0, cfg_tty, CFG_CMD_FILE, CFG_NEEDARG, "TTY",
        "Configure alternate TTY for slirp to use (Overrides SLIRP_TTY)" },
      { "nozeros", 0, cfg_nozeros, CFG_CMD_FILE, 0, "",
        "Disable 5 0's to exit, 5 1's to detach" },

	/* PPP options */
#ifndef USE_PPP
	  { "ppp", "-P", cfg_ppp, CFG_CMD_FILE, 0,
		  "",
		  "PPP not compiled into this slirp executable" },
#else
	  { "ppp", "-P", cfg_ppp, CFG_CMD_FILE, 0,
		  "",
		  "set unit to use PPP instead of SLIP" },
#endif

#ifdef USE_PPP
	  { "ppp_exit", 0, cfg_ppp_exit, CFG_ANY, 0,
		  "",
		  "make Slirp exit when PPP goes down" },
	  { "-all", 0, noopt, CFG_CMD_FILE, 0,
		  "",
		  "ppp: don't request/allow any options" },
	  { "-ac", 0, noaccomp, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable address/control compress" },
	  { "-am", 0, noasyncmap, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable asyncmap negotiation" },
	  { "asyncmap", "-as", setasyncmap, CFG_CMD_FILE, CFG_NEEDARG,
		  "ASYNCMAP",
		  "ppp: set the desired async map" },
	  { "debugppp", "-dppp", setdebug, CFG_ANY, 0,
		  "FILE",
		  "ppp: increase debugging level" },
	  { "-ip", 0, noipaddr, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable IP address negotiation" },
	  { "-mn", 0, nomagicnumber, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable magic number negotiation" },
	  { "-mru", 0, nomru, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable mru negotiation" },
	  { "-pc", 0, nopcomp, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable protocol field compress" },
	  { "+ua", 0, setupapfile, CFG_CMD_FILE, CFG_NEEDARG,
		  "FILE",
		  "ppp: get PAP user and password from file" },
	  { "+pap", 0, reqpap, CFG_CMD_FILE, 0,
		  "",
		  "ppp: require PAP auth from peer" },
	  { "-pap", 0, nopap, CFG_CMD_FILE, 0,
		  "",
		  "ppp: don't allow UPAP authentication with peer" },
	  { "+chap", 0, reqchap, CFG_CMD_FILE, 0,
		  "",
		  "ppp: require CHAP authentication from peer" },
	  { "-chap", 0, nochap, CFG_CMD_FILE, 0,
		  "",
		  "ppp: don't allow CHAP authentication with peer" },
	  { "-vj", 0, setnovj, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable VJ compression" },
	  { "-vjccomp", 0, setnovjccomp, CFG_CMD_FILE, 0,
		  "",
		  "ppp: disable VJ connection-ID compression" },
	  { "vj-max-slots", 0, setvjslots, CFG_CMD_FILE, CFG_NEEDARG,
		  "SLOTS",
		  "ppp: set maximum VJ header slots" },
	  { "escape", 0, setescape, CFG_CMD_FILE, CFG_NEEDARG,
		  "NUM[,NUM|-NUM][...]",
		  "ppp: set chars to escape on transmission" },
	  { "domain", 0, setdomain, CFG_CMD_FILE, CFG_NEEDARG,
		  "ADDR",
		  "ppp: add given domain name to hostname" },
#endif
	  { "mru", 0, setmru, CFG_CMD_FILE, CFG_NEEDARG,
		  "MRU",
		  "set MRU" },
	  { "mtu", 0, setmtu, CFG_CMD_FILE, CFG_NEEDARG,
		  "MTU",
		  "set MTU" },
#ifdef USE_PPP
	  { "initiate-options", 0, setinitopt, CFG_CMD_FILE, 0,
		  "",
		  "ppp: initiate the sending of options" },
	  { "name", 0, setname, CFG_CMD_FILE, CFG_NEEDARG,
		  "NAME",
		  "ppp: set local name for authentication" },
	  { "user", 0, set_user, CFG_CMD_FILE, CFG_NEEDARG,
		  "USERNAME",
		  "ppp: set username for PAP auth with peer" },
	  { "usehostname", 0, setusehostname, CFG_CMD_FILE, 0,
		  "",
		  "ppp: must use hostname for auth" },
	  { "remotename", 0, setremote, CFG_CMD_FILE, CFG_NEEDARG,
		  "HOSTNAME",
		  "ppp: set remote name for authentication" },
	  { "auth", 0, setauth, CFG_CMD_FILE, 0,
		  "",
		  "ppp: require authentication from peer" },
	  { "proxyarp", 0, setproxyarp, CFG_CMD_FILE, 0,
		  "",
		  "ppp: add proxy ARP entry" },
	  { "login", 0, setdologin, CFG_CMD_FILE, 0,
		  "",
		  "ppp: use system password database for UPAP" },
	  { "lcp-echo-failure", 0, setlcpechofails, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max number consecutive echo failures" },
	  { "lcp-echo-interval", 0, setlcpechointv, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: time for lcp echo events" },
	  { "lcp-restart", 0, setlcptimeout, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set timeout for LCP" },
	  { "lcp-max-terminate", 0, setlcpterm, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #xmits for term-reqs" },
	  { "lcp-max-configure", 0, setlcpconf, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #xmits for conf-reqs" },
	  { "lcp-max-failure", 0, setlcpfails, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #conf-naks for LCP" },
	  { "ipcp-restart", 0, setipcptimeout, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set timeout for IPCP" },
	  { "ipcp-max-terminate", 0, setipcpterm, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #xmits for term-reqs" },
	  { "ipcp-max-configure", 0, setipcpconf, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #xmits for conf-reqs" },
	  { "ipcp-max-failure", 0, setipcpfails, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #conf-naks for IPCP" },
	  { "pap-restart", 0, setpaptimeout, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set timeout for UPAP" },
	  { "pap-max-authreq", 0, setpapreqs, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #xmits for auth-reqs" },
	  { "pap-timeout", 0, setpapreqtime, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set PAP timeout" },
	  { "chap-restart", 0, setchaptimeout, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set timeout for CHAP" },
	  { "chap-max-challenge", 0, setchapchal, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set max #xmits for challenge" },
	  { "chap-interval", 0, setchapintv, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set interval for rechallenge" },
	  { "ipcp-accept-local", 0, setipcpaccl, CFG_CMD_FILE, 0,
		  "",
		  "ppp: accept peer's address for us" },
	  { "ipcp-accept-remote", 0, setipcpaccr, CFG_CMD_FILE, 0,
		  "",
		  "ppp: accept peer's address for it" },
	  { "bsdcomp", 0, setbsdcomp, CFG_CMD_FILE, CFG_NEEDARG,
		  "N",
		  "ppp: set bsdcomp" },
	  { "-bsdcomp", 0, setnobsdcomp, CFG_CMD_FILE, 0,
		  "",
		  "ppp: don't use bsdcomp" },
	  { "papcrypt", 0, setpapcrypt, CFG_CMD_FILE, 0,
		  "",
		  "ppp: crypt PAP authentication" },
#endif
	  { NULL, NULL, NULL, 0, 0, NULL, NULL }
};
