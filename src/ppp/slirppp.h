/*
 * slirppp.h - definitions
 * 
 * Juha Pirkola 1995
 *
 * included through ppp.h and SLiRP's main.c
 *
 */ 

#ifndef __SLIRPPP_H__
#define __SLIRPPP_H__

#define PPP_LOGFILE	"ppplog"

/* special characters */
/* #define PPP_FLAG        0x7E */   /* frame delimiter */
#define PPP_ESC         0x7d    /* escape character */

/* protocols */
#define PROTO_IP       0x0021
#define PROTO_VJCOMP   0x002d
#define PROTO_VJUNCOMP 0x002f

/* FCS support */
#define PPP_FCS_INIT   0xffff
#define PPP_FCS_GOOD   0xf0b8


#define in_xmap(c, unit)  (xmit_async_map[unit][(c) >> 5] & (1 << ((c) & 0x1f)))
#define in_rmap(c, unit)  ((((unsigned int) (unsigned char) (c)) < 0x20) && \
                        recv_async_map[unit] & (1 << (c)))

#ifndef GIDSET_TYPE			/* I'm not sure who needs this */
#define GIDSET_TYPE gid_t
#endif

#ifdef __linux__			/* Maybe both should be undef'd ? */
#define _linux_
#endif
										
struct ppp_out {
	unsigned char *buff;
	unsigned char *head;
	unsigned short fcs;
};

extern int debug;
extern int ppp_up;
extern FILE *logfile;

#endif /* __SLIRPPP_H__ */
