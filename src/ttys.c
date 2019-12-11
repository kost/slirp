/*
 * Copyright (c) 1995, Danny Gasparovski
 * Parts Copyright (c) 2001 Kelly "STrRedWolf" Price
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#ifdef FULL_BOLT
#define WANT_SYS_IOCTL_H
#endif
#include <slirp.h>

struct ttys *ttys_unit[MAX_INTERFACES];

int slirp_forked;

struct ttys *
tty_attach(unit, device)
	int unit;
	char *device;
{
	char buff[256], *bptr;
	struct ttys *ttyp, *ttyp_tmp, *ttyp_last = 0;
	struct stat stat;

	DEBUG_CALL("tty_attach");
	DEBUG_ARG("unit = %d", unit);
	DEBUG_ARG("device = %lx", (long)device);

	if ((ttyp = (struct ttys *)malloc(sizeof(struct ttys))) == NULL)
	    return 0;
	memset(ttyp, 0, sizeof(struct ttys));
	ttyp->next = 0;
	ttyp->fd = 0; /* Default changed from -1 -RedWolf */

	/* Only open the device if there is one */
	if (device) {
		if ((ttyp->fd = open(device, O_RDWR )) < 0) {
			free(ttyp);
			return 0; /* XXXXX */
		}
        lprint ("Opening device %s...\r\n\r\n", device);
	}

	/* Link it to the *tail* of the list XXXXX */
	if (!ttys) {
		ttys = ttyp;
	} else {
		for (ttyp_tmp = ttys; ttyp_tmp; ttyp_tmp = ttyp_tmp->next)
		   ttyp_last = ttyp_tmp;
		/* XXX More checks? */
		ttyp_last->next = ttyp;
	}

#ifdef FULL_BOLT
	fd_nonblock(ttyp->fd);
#endif

	if (ttyp->fd >= 0 && isatty(ttyp->fd) && fstat(ttyp->fd, &stat) == 0) {
		/* Save the current permissions */
		ttyp->mode = stat.st_mode;
#ifdef HAVE_FCHMOD
		fchmod(ttyp->fd, S_IRUSR|S_IWUSR);
#else
		chmod(ttyname(ttyp->fd), S_IRUSR|S_IWUSR);
#endif
	}

	ttyp->unit = unit;
#ifndef FULL_BOLT
	ttyp->towrite = towrite_max;
#endif
#ifndef FULL_BOLT
	ttyp->baud = DEFAULT_BAUD;
	ttyp->bytesps = ttyp->baud/10;
#endif
	ttyp->lastime = curtime;
	ttyp->sc_xc_state = 0;
	ttyp->sc_rc_state = 0;

	/* Default is SLIP */
	ttyp->proto = PROTO_SLIP;
	ttyp->up = 1; /* SLIP is always up */
	ttyp->if_input = sl_input;
	ttyp->if_encap = sl_encap;
	ttys_unit[unit] = ttyp;

	/* Rawify the terminal, if applicable */
	if (ttyp->fd >= 0)
	   term_raw(ttyp);

	/* Config the new tty */
	if ((bptr = (char *)getenv("HOME")))
	   sprintf(buff, "%s/.slirprc-%d", bptr, unit);
	else
	   sprintf(buff, ".slirprc-%d", unit);
	config(buff, ttyp->unit);

	return ttyp;
}

void
tty_detached(ttyp, exiting)
	struct ttys *ttyp;
	int exiting;
{
	struct ttys *ttyp_tmp, *ttyp_last = 0;

	DEBUG_CALL("tty_detached");
	DEBUG_ARG("ttyp = %lx", (long)ttyp);
	DEBUG_ARG("exiting = %d", exiting);

	/* First, remove ttyp from the queue */
	if (ttyp == ttys) {
		ttys = ttys->next;
	} else {
		for (ttyp_tmp = ttys; ttyp_tmp; ttyp_tmp = ttyp_tmp->next) {
			if (ttyp_tmp == ttyp)
			   break;
			ttyp_last = ttyp_tmp;
		}
		if (!ttyp_last) { /* XXX */
			/* Can't find it *shrug* */
			return;
		}
		ttyp_last->next = ttyp->next;
	}

	term_restore(ttyp);

#ifdef FULL_BOLT
	fd_block(ttyp->fd);
#endif

	/* Restore device mode */
	if (ttyp->mode)
	   fchmod(ttyp->fd, ttyp->mode);

	/* Bring the link down */

#ifdef USE_PPP
	/*
	 * Call lcp_lowerdown if it's ppp
	 */
	if (ttyp->proto == PROTO_PPP) {
		lcp_lowerdown(ttyp->unit);
		phase = PHASE_DEAD; /* XXXXX */
	}
#endif
	/*
	 * Kill the guardian, if it exists
	 */
	if (ttyp->pid)
	   kill(ttyp->pid, SIGQUIT);

	/*
	 * If this was the last tty and we're not restarting, exit
	 */
	if (!ttys && slirp_socket < 0 && !exiting)
	   slirp_exit(0);

    if(ttyp->fd != 0)   /* Dont close stdin, we need it on exit */
	    close(ttyp->fd);
	if (ttyp->m)
	    m_free(ttyp->m);

	/*
	 * If this was the controlling tty, call ctty_detached
	 */
	if ((ttyp->flags & TTY_CTTY) && !exiting)
	   ctty_detached();

#ifdef USE_PPP
	/* Deallocate compress data */
	ppp_ccp_closed(ttyp);
#endif

	ttys_unit[ttyp->unit] = 0;
	
	/*
	 * If you love it, set it free() ...
	 * If it comes back, we have a memory leak
	 */
	free(ttyp);
	
	detach_time = curtime;
}

/*
 * Called when controlling tty has detached
 */
void
ctty_detached()
{
	int retval;
	
	DEBUG_CALL("ctty_detached");
	
	ctty_closed = 0;
	
	/*
	 * Song and dance to detach from ctty but not be orphaned.  This
	 * madness is because we don't want to stay attached to the old
	 * tty (thus potentially blocking it, or getting random signals
	 * from it), but if we detach from it with setsid(), we end up
	 * as an "orphaned process group".  As such we can't write to
	 * another terminal, so we fork once and have the child start a
	 * new process group, which makes the child not an orphan, but
	 * clutters up the process table with yet a third slirp process.
	 * Better ways to do this would be most appreciated.
	 */
	if (slirp_forked) {
		/* Shouldn't happen, but don't want to fork() again if it does */
		return;
	}

	/* Really get detached */
	if (fork())
	   exit(0);

	(void) setsid();        /* new session */
	retval = fork();
	if (retval < 0)
	   return; /*shrug*/
	if (retval) /* parent idles *sigh* */
	   snooze();
	slirp_forked = 1;

	retval = setpgid(0, 0); /* child in new process group */
/*	if (retval < 0)
 *	   return;
 */
	/*
	 * Nuke stdin to get off old, useless tty
	 * (stdout and stderr were already nuked in main_init())
	 */
	retval = open("/dev/null", O_RDWR);
	dup2(retval, 0);
	if (retval > 0)
	   close(retval);
}

