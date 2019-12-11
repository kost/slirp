/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */

#ifdef sc_flags
#undef sc_flags
#endif

#ifndef INCLUDED_TERMIOS_H
# ifdef HAVE_TERMIOS_H
#  include <termios.h>
# else
#  include <termio.h>
# endif
# define INCLUDED_TERMIOS_H
#endif

struct ttys {
	int unit;		/* Unit number of this ttys */
	int proto;		/* Protocol used */
	int up;			/* Is the interface up? */

	int fd;			/* File Descriptor */
	int pid;		/* PID of the "guardian", if any */

#define IF_OUTBUFFSIZE 2*2048+2
#ifdef FULL_BOLT
	char if_outbuff[IF_OUTBUFFSIZE];
	int nbuff;
	int nbuff_written;
#else
	int towrite;		/* towrite for this tty */
#endif

	int zeros;		/* Number of '0's typed */
	int ones;		/* Number of '1's typed */
	struct mbuf *m;		/* Input mbuf for this tty */
	int msize;		/* Size of the above */
	u_char *mptr;		/* Ptr to the above */
	u_char esc;		/* Flag to indicate the next byte is escaped */
	int mbad;		/* The receiving packet is bad */
	int inpkt;		/* We are receiving a packet */

#ifndef FULL_BOLT
	int baud;		/* Baudrate */
	int bytesps;		/* Bytes per second */
#endif

	u_int lastime;		/* for updtime() */

	struct termios oldterm;	/* Old termios for the tty */
	mode_t mode;

	struct slirp_ifstats ifstats;	/* Interface statistics */

	u_int flags;		/* Misc flags, see below */
	void (*if_input) _P((struct ttys *, u_char *, int)); /* packet decapsulation and dispatch */
	int (*if_encap) _P((char *, struct mbuf *, int, int, int)); /* packet encapsulation routine */

	/* The following fields are for compression
	 * XXX should put them around ifdef's
	 */
	u_int sc_flags;
	struct compressor *sc_rcomp;
	struct compressor *sc_xcomp;
	void *sc_rc_state;
	void *sc_xc_state;
#if MS_DCC
    int dccpos;     /* chat hack, see if got CLIENT string */
#endif

	struct ttys *next;	/* Linked list */
};

extern struct ttys *ttys;

#define TTY_CTTY 0x1
#ifdef USE_PPP
#define TTY_PPPSTART 0x2
#endif

/* SC flags */
#define SC_VJ_RESET 0x1
#define SC_DECOMP_RUN 0x2
#define SC_DC_ERROR 0x4
#define SC_DC_FERROR 0x8
#define SC_COMP_RUN 0x10
#define SC_CCP_UP 0x20
#define SC_CCP_OPEN 0x40

extern int slirp_forked;
