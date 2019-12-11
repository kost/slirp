/*
 * main.c - Point-to-Point Protocol main module
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static char rcsid[] = "$Id: main.c,v 1.24 1995/06/12 11:22:49 paulus Exp $";
#endif

#include <stdio.h>
/* #include <stdlib.h> */
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <utmp.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "pppd.h"
#include "magic.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#include "upap.h"
#include "chap.h"
#include "ccp.h"
#include "pathnames.h"
#include "patchlevel.h"

#undef ifs_next

#include <net/if.h>	/* must follow include of slirp.h via pppd.h */

/*
 * If REQ_SYSOPTIONS is defined to 1, pppd will not run unless
 * /etc/ppp/options exists.
 */

/* XXXXX Delete fields not used */

#ifndef	REQ_SYSOPTIONS
#define REQ_SYSOPTIONS	1
#endif

/* interface vars */
char ifname[MAX_INTERFACES];		/* Interface name */
int ifunit;			/* Interface unit number */

char hostname[MAXNAMELEN];	/* Our hostname */
static char pidfilename[MAXPATHLEN];	/* name of pid file */
static char default_devnam[MAXPATHLEN];	/* name of default device */
static pid_t	pid;		/* Our pid */
static pid_t	pgrpid;		/* Process Group ID */
static uid_t uid;		/* Our real user-id */

int fd = -1;			/* Device file descriptor */

struct timeval schedtime;

int phase;			/* where the link is at */
int kill_link;

static int initfdflags = -1;	/* Initial file descriptor flags */

u_char outpacket_buf[PPP_MRU+PPP_HDRLEN]; /* buffer for outgoing packet */
/* static u_char inpacket_buf[PPP_MRU+PPP_HDRLEN]; */ /* buffer for incoming packet */

int hungup;			/* terminal has been hung up */
static int n_children;		/* # child processes still running */

int baud_rate;

/* prototypes */
static void hup __P((int));
static void term __P((int));
static void chld __P((int));
static void toggle_debug __P((int));
static void open_ccp __P((int));

static void get_input __P((void));
void establish_ppp __P((void));
void calltimeout __P((void));
struct timeval *timeleft __P((struct timeval *));
void reap_kids __P((void));
void cleanup __P((int, caddr_t));
void close_fd __P((void));
void die __P((int));
void novm __P((char *));

void log_packet __P((u_char *, int, char *));
void format_packet __P((u_char *, int,
			   void (*) (void *, char *, ...), void *));
void pr_log __P((void *, char *, ...));

extern	char	*ttyname __P((int));
extern	char	*getlogin __P((void));

#ifdef ultrix
#undef	O_NONBLOCK
#define	O_NONBLOCK	O_NDELAY
#endif

/*
 * PPP Data Link Layer "protocol" table.
 * One entry per supported protocol.
 */
struct protent prottbl[] = {
    { PPP_LCP, lcp_init, lcp_input, lcp_protrej,
	  lcp_printpkt, NULL, "LCP" },
    { PPP_IPCP, ipcp_init, ipcp_input, ipcp_protrej,
	  ipcp_printpkt, NULL, "IPCP" },
    { PPP_PAP, upap_init, upap_input, upap_protrej,
	  upap_printpkt, NULL, "PAP" },
    { PPP_CHAP, ChapInit, ChapInput, ChapProtocolReject,
	  ChapPrintPkt, NULL, "CHAP" },
    { PPP_CCP, ccp_init, ccp_input, ccp_protrej,
	  ccp_printpkt, ccp_datainput, "CCP" },
};

/*
 * demuxprotrej - Demultiplex a Protocol-Reject.
 */
void
demuxprotrej(unit, protocol)
    int unit;
    u_short protocol;
{
    int i;

    /*
     * Upcall the proper Protocol-Reject routine.
     */
    for (i = 0; i < sizeof (prottbl) / sizeof (struct protent); i++)
	if (prottbl[i].protocol == protocol) {
	    (*prottbl[i].protrej)(unit);
	    return;
	}

    do_syslog(LOG_WARNING,
	   "demuxprotrej: Unrecognized Protocol-Reject for protocol 0x%x",
	   protocol);
}


/*
 * quit - Clean up state and exit.
 */
void 
quit()
{
    die(0);
}

struct callout {
    int	c_time;		/* time at which to call routine */
    caddr_t		c_arg;		/* argument to routine */
    void		(*c_func)();	/* routine */
    struct		callout *c_next;
};

static struct callout *callout = NULL;	/* Callout list */
static struct timeval timenow;		/* Current time */

/*
 * timeout - Schedule a timeout.
 *
 * Note that this timeout takes the number of seconds, NOT hz (as in
 * the kernel).
 */
void
timeout(func, arg, time)
    void (*func)();
    caddr_t arg;
    int time;
{
	struct itimerval itv;
	struct callout *newp, **oldpp;
	
	MAINDEBUG((LOG_DEBUG, "Timeout %x:%x in %d seconds.",
		   (int) func, (int) arg, time));
	
	/*
	 * Allocate timeout.
	 */
	if ((newp = (struct callout *) malloc(sizeof(struct callout))) == NULL) {
		do_syslog(LOG_ERR, "Out of memory in timeout()!");
		die(1);
	}
	newp->c_arg = arg;
	newp->c_func = func;
	
	/*
	 * Find correct place to link it in and decrement its time by the
	 * amount of time used by preceding timeouts.
	 */
	for (oldpp = &callout;
	     *oldpp && (*oldpp)->c_time <= time;
	     oldpp = &(*oldpp)->c_next)
	   time -= (*oldpp)->c_time;
	newp->c_time = time;
	newp->c_next = *oldpp;
	if (*oldpp)
	   (*oldpp)->c_time -= time;
	*oldpp = newp;
	
	/*
	 * If this is now the first callout then we have to set a new
	 * itimer.
	 */
	if (callout == newp) {
		itv.it_interval.tv_sec = itv.it_interval.tv_usec =
		itv.it_value.tv_usec = 0;
		itv.it_value.tv_sec = callout->c_time;
		MAINDEBUG((LOG_DEBUG, "Setting itimer for %d seconds in timeout.",
			   itv.it_value.tv_sec));
		if (setitimer(ITIMER_REAL, &itv, NULL)) {
			
			do_syslog(LOG_ERR, "setitimer(ITIMER_REAL): %m");
			die(1);
		}
		if (gettimeofday(&schedtime, NULL)) {
			do_syslog(LOG_ERR, "gettimeofday: %m");
			die(1);
		}
	}
}

/*
 * untimeout - Unschedule a timeout.
 */
void
untimeout(func, arg)
    void (*func)();
    caddr_t arg;
{
	struct itimerval itv;
	struct callout **copp, *freep;
	int reschedule = 0;
	
	MAINDEBUG((LOG_DEBUG, "Untimeout %x:%x.", (int) func, (int) arg));
	
	/*
	 * If the first callout is unscheduled then we have to set a new
	 * itimer.
	 */
	if (callout &&
	    callout->c_func == func &&
	    callout->c_arg == arg)
	   reschedule = 1;
	
	/*
	 * Find first matching timeout.  Add its time to the next timeouts
	 * time.
	 */
	for (copp = &callout; *copp; copp = &(*copp)->c_next)
	   if ((*copp)->c_func == func &&
	       (*copp)->c_arg == arg) {
		   freep = *copp;
		   *copp = freep->c_next;
		   if (*copp)
		      (*copp)->c_time += freep->c_time;
		               (void) free((char *) freep);
		   break;
	   }
	
	if (reschedule) {
		itv.it_interval.tv_sec = itv.it_interval.tv_usec =
		itv.it_value.tv_usec = 0;
		itv.it_value.tv_sec = callout ? callout->c_time : 0;
		MAINDEBUG((LOG_DEBUG, "Setting itimer for %d seconds in untimeout.",
			   itv.it_value.tv_sec));
		if (setitimer(ITIMER_REAL, &itv, NULL)) {
			do_syslog(LOG_ERR, "setitimer(ITIMER_REAL): %m");
			die(1);
		}
		if (gettimeofday(&schedtime, NULL)) {
			do_syslog(LOG_ERR, "gettimeofday: %m");
			die(1);
		}
	}
}

/*
 * alrm - Catch SIGALRM signal.
 *
 * Indicates a timeout.
 */
void                                                    /* static removed by JP */
alrm(sig)
    int sig;
{
	struct itimerval itv;
	struct callout *freep, *list, *last;
	
	MAINDEBUG((LOG_DEBUG, "Alarm"));
	
	if (callout == NULL)
	   return;
	/*
	 * Get the first scheduled timeout and any that were scheduled
	 * for the same time as a list, and remove them all from callout
	 * list.
	 */
	list = last = callout;
	while (last->c_next != NULL && last->c_next->c_time == 0)
	   last = last->c_next;
	callout = last->c_next;
	last->c_next = NULL;
	
	/*
	 * Set a new itimer if there are more timeouts scheduled.
	 */
	if (callout) {
		itv.it_interval.tv_sec = itv.it_interval.tv_usec = 0;
		itv.it_value.tv_usec = 0;
		itv.it_value.tv_sec = callout->c_time;
		MAINDEBUG((LOG_DEBUG, "Setting itimer for %d seconds in alrm.",
			   itv.it_value.tv_sec));
		if (setitimer(ITIMER_REAL, &itv, NULL)) {
			do_syslog(LOG_ERR, "setitimer(ITIMER_REAL): %m");
			die(1);
		}
		if (gettimeofday(&schedtime, NULL)) {
			do_syslog(LOG_ERR, "gettimeofday: %m");
			die(1);
		}
	}
	
	/*
	 * Now call all the timeout routines scheduled for this time.
	 */
	while (list) {
		(*list->c_func)(list->c_arg);
		freep = list;
		list = list->c_next;
		(void) free((char *) freep);
	}
}


/*
 * novm - log an error message saying we ran out of memory, and die.
 */
void
novm(msg)
    char *msg;
{
    do_syslog(LOG_ERR, "Virtual memory exhausted allocating %s\n", msg);
    die(1);
}
