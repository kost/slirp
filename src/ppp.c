/*
 * ppp.c - interface between SLiRP and ppp-2.1.2b package
 *
 *  Copyright (c) 1995 Juha Pirkola 
 *  
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. All advertising materials mentioning features or use of this software
 *     must display the following acknowledgement:
 *       This product includes software developed by Juha Pirkola.
 * 
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE  IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 *  JUHA PIRKOLA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * This file adds PPP functionality to SLiRP, a free SLIP emulator
 * by Danny Gasparovski, using the free PPP package ppp-2.1.2b
 * maintained by Paul Mackerras.
 *
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <utmp.h>
#include <pwd.h>
#include <ctype.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
/* #include <net/if.h> */
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#else
#include <termio.h>
#endif

#include "ppp/ppp.h"
#include "ppp/magic.h"
#include "ppp/fsm.h"
#include "ppp/lcp.h"
#include "ppp/ipcp.h"
#include "ppp/upap.h"
#include "ppp/chap.h"

#include "ppp/pppd.h"
#include "ppp/pathnames.h"

#include <slirp.h>

#include "ppp/ppp-comp.h"
#include "ppp/bsd-comp.h"

extern struct compressor ppp_bsd_compress;

struct compressor *ppp_compressors[2] = {
#if DO_BSD_COMPRESS
	&ppp_bsd_compress,
#endif
	NULL
};

extern struct protent prottbl[];

#define N_PROTO         5		/* Nr of protocol entries	*/
					/* in prottbl			*/



/* Lookup table for checksum calculation. From RFC-1662			*/

static unsigned short fcstab[256] = {
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};


u_int32_t recv_async_map[NUM_PPP];		/* which received characters to ignore	*/
u_int32_t xmit_async_map[NUM_PPP][8];	/* which xmitted characters to escape	*/
int proto_field_comp[NUM_PPP];		/* compressing the protocol field ?	*/
int addr_field_comp[NUM_PPP];		/* compressing the address field ?	*/
FILE *logfile;			/* where to log events			*/
int ppp_exit;			/* Exit when PPP goes down */


/*
 * stuff character in the output buffer, escaped if mentioned
 * in xmit_async_map, and update the check sum
 */
void
stuff_char(c, unit, outp)
	int c;
	int unit;
	struct ppp_out *outp;
{
	c &= 0xff;
       	if  (in_xmap(c, unit)){
		*outp->head++ = PPP_ESC;
                *outp->head++ = c^PPP_TRANS;
       	} else
             	*outp->head++ = c;
       	outp->fcs = (outp->fcs >> 8) ^ fcstab[(outp->fcs ^ c) & 0xff];
}

/*
 * Add a two byte check sum to the end of the outgoing packet
 */
void
add_fcs(outp, unit)
	struct ppp_out *outp;
	int unit;
{
       u_short s = outp->fcs;

       s ^= 0xffff;
       stuff_char(s & 0xff, unit, outp);
       stuff_char(s >> 8, unit, outp);
}

/*
 * check the check sum of an incoming frame
 */
int
check_fcs(buff, len)
	u_char *buff;
	int len;
{
        u_short fcs = PPP_FCS_INIT;
        u_char *c = buff;
        int i;

        for (i = 0; i < len ; i++, c++)
        fcs = (fcs >> 8) ^ fcstab[(fcs ^ *c) & 0xff];

        if (fcs == PPP_FCS_GOOD)
        	return 1;
        else {
		do_syslog(0, "check_fcs: Checksum error, packet length = %d", len);

        /* Spit out faulty packets when debugging. */
        if(debug) {
            for(i=0;i < len ; i++)
                fprintf(logfile, "%c:%02x ", iscntrl(buff[i]) ? '.' : buff[i] , buff[i] & 0xff);
            fprintf(logfile, "\n");
        }

		return 0;
	}
}


/*
 * IPCP tells us that the link is broken, we're not allowed
 * pass IP packets
 */
int
sifdown(unit)
	int unit;
{
	struct ttys *ttyp = ttys_unit[unit];

	if (!ttyp)
	   return 0; /* *shrug* */

	ttyp->up = 0;
	do_syslog(0, "slirppp: PPP is down now");
	return 1;
}

/*
 * IPCP says link is open, we can pass IP packets
 */
int
sifup (unit)
	int unit;
{
	struct ttys *ttyp = ttys_unit[unit];

	if (!ttyp)
	   return 0; /* *shrug* */

	ttyp->up = 1;
	do_syslog(0, "slirppp: PPP is up now");
	return 1;
}


/*
 * configure receive characteristics after negotiations
 * we don't really care about pcomp and accomp, because compression
 * can be directly detected from the incoming packet
 */
void
ppp_recv_config (unit, mru, asyncmap, pcomp, accomp)
	int unit, mru;
	u_int32_t asyncmap;
	int pcomp, accomp;
{
	recv_async_map[unit] = asyncmap;
	do_syslog(0, "ppp_recv_config: (recv) asyncmap set to %08lx", asyncmap);
	do_syslog(0, "               :  mru set to %d", mru);
}

/*
 * set the transmit asyncmap, in other words the characters to
 * be escaped when transmitted
 */

void
ppp_set_xaccm(unit, accm)
	int unit;
	u_int32_t *accm;
{
	memcpy(xmit_async_map[unit], accm, sizeof(accm[0]) * 8);
	do_syslog(0, "ppp_set_xaccm: extended xmit asyncmap set to %08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx",
		  accm[7], accm[6], accm[5], accm[4], accm[3], accm[2], accm[1], accm[0]);
}

/*
 * configure our receive characteristic after negotiations
 */
void
ppp_send_config (unit, mtu, asyncmap, pcomp, accomp)
	int unit, mtu;
	u_int32_t asyncmap;
	int pcomp, accomp;
{
	if_mtu = MIN(mtu, if_mtu);
	do_syslog(0, "ppp_send_config: mtu set to %d", if_mtu);
	xmit_async_map[unit][0] = asyncmap;
	do_syslog(0, "ppp_send_config: (xmit) asyncmap set to %08lx", asyncmap);
	proto_field_comp[unit] = pcomp;
	if (pcomp)
		do_syslog(0, "ppp_send_config: compressing the protocol field");
	addr_field_comp[unit] = accomp;
	if (accomp)
		do_syslog(0, "ppp_send_config: compressing the address field");

}

/*
 * set TCP/IP header compression mode according to what
 * has been negotiated
 * I don't know what to do with cidcomp and maxcid
 * must fix later
 */
void
sifvjcomp (unit, vjcomp, cidcomp, maxcid)
	int unit, vjcomp, cidcomp, maxcid;
{
	if (vjcomp) {
		if_comp &= ~(IF_AUTOCOMP|IF_NOCOMPRESS);
		if_comp |= IF_COMPRESS;
		do_syslog(0, "sifvjcomp: Using VJ header compression");
	} else {
		if_comp &= ~(IF_AUTOCOMP|IF_COMPRESS);
		if_comp |= IF_NOCOMPRESS;
		do_syslog(0, "sifvjcomp: Not using VJ header compression");
	}

	if (cidcomp) {
		if_comp &= ~IF_NOCIDCOMP;
	} else {
		if_comp |= IF_NOCIDCOMP;
	}
}

/*
 * now we have a frame from ppp_input
 * if the protocol field says that it is an IP packet, copy
 * the it to a mbuf and deliver to slirps ip_input function
 */

void
doframe(ttyp)
	struct ttys *ttyp;
{
	u_short proto;
	int i, unit = ttyp->unit;
	struct mbuf *m = ttyp->m, *dmp = NULL;
	int rv;

	if (!check_fcs(mtod(m, u_char *), m->m_len)) {
		ttyp->sc_flags |= SC_VJ_RESET;
		ttyp->ifstats.in_errpkts++;
		ttyp->ifstats.in_errbytes += m->m_len;
		m_free(m);
		return;
	}

	m->m_len -= 2; /* Drop trailing fcs */

	if (((u_char)m->m_data[0] == ALLSTATIONS) && (u_char)(m->m_data[1] == UI)) {
		m->m_data += 2;
		m->m_len -= 2; /* Drop address field */
	}

	proto = (u_short)*(u_char *)m->m_data++;
	if (proto & 1) {
		m->m_len--;
	} else {
		/* XXX */
		proto = (proto << 8) | ((u_short)*(u_char *)m->m_data++);
		m->m_len -= 2; /* Drop protocol field */
	}

	do_syslog(0, "Received a packet of %d bytes, protocol = 0x%04x",
		  m->m_len, proto);

	/* XXXXX HACK! */
	if (m->m_len < 0)
	   m->m_len = 0;

	/*
	 * Decompress this packet if necessary, update the receiver's'
	 * dictionary, or take appropriate action on a CCP packet.
	 */
	if (proto == PPP_COMP && ttyp->sc_rc_state && (ttyp->sc_flags & SC_DECOMP_RUN)
	    && !(ttyp->sc_flags & SC_DC_ERROR) && !(ttyp->sc_flags & SC_DC_FERROR)) {
		/* decompress this packet */
		rv = (*ttyp->sc_rcomp->decompress)(ttyp->sc_rc_state, m, &dmp);
		if (rv == DECOMP_OK) {
			m_free(m);
			if (dmp == NULL) {
				/* no error, but no decompressed packet produced */
				return;
			}
			m = dmp;
			/* the first byte is the old protocol */
			proto = (u_char)*m->m_data++;
			m->m_len--;
		} else {
			/*
			 * An error has occurred in decompression.
			 * Pass the compressed packet up to pppd, which may take
			 * CCP down or issue a Reset-Req.
			 */
			ttyp->sc_flags |= SC_VJ_RESET;
			if (rv == DECOMP_ERROR)
				ttyp->sc_flags |= SC_DC_ERROR;
			else
				ttyp->sc_flags |= SC_DC_FERROR;
		}
	} else {
		if (ttyp->sc_rc_state && (ttyp->sc_flags & SC_DECOMP_RUN))
		   (*ttyp->sc_rcomp->incomp)(ttyp->sc_rc_state, m, proto);
		if (proto == PPP_CCP)
		   ppp_ccp(ttyp, mtod(m, u_char *), m->m_len, 1);
	}

	if (ttyp->sc_flags & SC_VJ_RESET) {
		/*
		 * XXX This may be inefficient... when the header is NOT
		 * damaged, uncompressing it can get a good header, which
		 * will help fast recovery... still...
		 */
		sl_uncompress_tcp(NULL, 0, TYPE_ERROR, &comp_s);
		ttyp->sc_flags &= ~SC_VJ_RESET;
		ttyp->ifstats.in_errpkts++;
		ttyp->ifstats.in_errbytes += m->m_len;
	}

	/*
	 * Align here because the proto field in PPP will unalign
	 * the whole packet, and sl_uncompress_tcp grabs some IP
	 * fields
	 */
	if (proto != PROTO_VJCOMP && ((long)m->m_data & 3)) {
		ipstat.ips_unaligned++;
		memmove((u_char *)(m->m_data - ((long)m->m_data & 3)),
		    m->m_data, m->m_len);
		m->m_data -= ((long)m->m_data) & 3;
	}


	switch (proto) {
	 case PROTO_VJUNCOMP:
		if (ttyp->up) {
			m->m_len = sl_uncompress_tcp((u_char **)&m->m_data, m->m_len,
						     (u_int) TYPE_UNCOMPRESSED_TCP, &comp_s);
		}
		goto proto_ip;
	 case PROTO_VJCOMP:
		if (ttyp->up) {
			m->m_len = sl_uncompress_tcp((u_char **)&m->m_data, m->m_len,
						     (u_int) TYPE_COMPRESSED_TCP, &comp_s);
		}
proto_ip:
		if (m->m_len < 0)
		   goto dump;
		/* FALLTHROUGH */
	 case PROTO_IP:
		if (!ttyp->up) {
dump:
			ttyp->ifstats.in_errpkts++;
			ttyp->ifstats.in_errbytes += m->m_len;
			m_free(m);
			break;
		}
		ttyp->ifstats.in_pkts++;
		ttyp->ifstats.in_bytes += m->m_len;
		ip_input(m);
		break;

	 default:

		/* If LCP isn't up, and it's not an LCP, dump it */
		if (proto != PPP_LCP && lcp_fsm[ttyp->unit].state != OPENED) {
			m_free(m);
			return;
		}

		for (i = 0; i < N_PROTO; i++) {
			if (prottbl[i].protocol == proto) {
				(*prottbl[i].input)(unit, mtod(m, u_char *), m->m_len);
free_it:
				ttyp->ifstats.in_pkts++;
				ttyp->ifstats.in_bytes += m->m_len;
				m_free(m);
				return;
			}
			if (prottbl[i].datainput
			    && proto == (prottbl[i].protocol & ~0x8000)) {
				(*prottbl[i].datainput)(unit, mtod(m, u_char *), m->m_len);
				goto free_it;
			}
		}

/*		lcp_sprotrej(0, p - PPP_HDRLEN, len + PPP_HDRLEN); */ /* XXXXX */
		m_free(m);
		return;
	}
}


/*
 * the main input routine corresponding to sl_input
 * I tried to make this similar to sl_input, but it was not
 * possible to write the unescaped data directly to a mbuf,
 * and therefore this is a bit different
 */
void
ppp_input(ttyp, if_bptr, if_n)
	struct ttys *ttyp;
	u_char *if_bptr;
	int if_n;
{
	DEBUG_CALL("ppp_input");
	DEBUG_ARG("ttyp = %lx", (long)ttyp);
	DEBUG_ARG("if_bptr = %lx", (long)if_bptr);
	DEBUG_ARG("if_n = %d", if_n);

	for(; if_n; if_bptr++, if_n--) {
		if (*if_bptr == PPP_FLAG) {
            DEBUG_MISC((dfd, "ppp_flag"));
			if (ttyp->inpkt == 0)
                {
                DEBUG_MISC((dfd, "not inpkt"));
			   continue;
               }
			if (ttyp->esc) {
				ttyp->ifstats.in_mbad++;
				ttyp->mbad = 1;
                DEBUG_MISC((dfd, "mbad"));
			}
			ttyp->m->m_len = (char *)ttyp->mptr - (char *)ttyp->m->m_data;
			if (!ttyp->mbad) {
                DEBUG_MISC((dfd, "doframe"))
				doframe(ttyp);
			} else {
				m_free(ttyp->m);
				do_syslog(0, "ppp_input: Got a bad frame of %d bytes", ttyp->m->m_len);
			}
			ttyp->m = 0;
			ttyp->inpkt = 0;
			continue;
		}

		/* We fall here if it was not PPP_FLAG */
		if (ttyp->inpkt == 0) { /* new frame starting */
			ttyp->inpkt = 1;
			ttyp->m = m_get();
			ttyp->m->m_data += if_maxlinkhdr; /* Allow for uncompress */
			ttyp->mptr = mtod(ttyp->m, u_char *);
			ttyp->msize = M_FREEROOM(ttyp->m);
			ttyp->esc = 0;
			ttyp->mbad = 0;
		}

		if (!ttyp->mbad) {
			if (*if_bptr == PPP_ESC) {
                DEBUG_MISC((dfd, "ppp_esc"));
				ttyp->esc = 1;
				ttyp->inpkt = 1; /* XXX */
			} else if (!in_rmap(*if_bptr, ttyp->unit)) {
				if (ttyp->esc) {
					*ttyp->mptr++ = *if_bptr ^ PPP_TRANS;
					ttyp->esc = 0;
				} else
					*ttyp->mptr++ = *if_bptr;

				if (--ttyp->msize < 0) {
					ttyp->ifstats.in_mbad++;
					ttyp->mbad = 1;             /* frame too long */
					do_syslog(0, "ppp_input: Frame too long");
				}
			}
		}
	}
}


/*
 * this is the output function SLiRP uses, corresponding to sl_encap.
 * data from a mbuf is encapsulated according to the HDLC-like
 * framing scheme (RFC-1662) and put to the buffer pointed by inbptr
 * Note: This is only called on PROT_IP packets, all other protocol
 * packets use output()
 */
int
ppp_encap(inbptr, m, unit, ppp_esc, proto)
	char *inbptr;
	struct mbuf *m;
	int unit;
	int ppp_esc;
	int proto;
{
	int i;
	int slen, clen;
	struct ppp_out out;
	struct mbuf *mcomp = NULL;
	struct ttys *ttyp = ttys_unit[unit];

	DEBUG_CALL("ppp_encap");
	DEBUG_ARG("inbptr = %lx", (long)inbptr);
	DEBUG_ARG("m = %lx", (long)m);
	DEBUG_ARG("unit = %d", unit);
	DEBUG_ARG("ppp_esc = %lx", (long)ppp_esc);
	
	out.buff = out.head = (u_char *) inbptr;
	out.fcs = PPP_FCS_INIT;
	if (ppp_esc)
	   *out.head++ = PPP_FLAG;
	
	/*
	 * See what type of packet it is (returned by sl_compress_tcp)
	 * and make proto into the corresponding PPP protocol number
	 */
	switch(proto) {
	 case TYPE_IP:
		proto = PROTO_IP;
		break;
	 case TYPE_UNCOMPRESSED_TCP:
		proto = PROTO_VJUNCOMP;
		break;
	 case TYPE_COMPRESSED_TCP:
		proto = PROTO_VJCOMP;
		break;
	 default:
		/* Shouldn't happen */
		return -1;
	}
	
	if (ttyp->sc_xc_state && (ttyp->sc_flags & SC_COMP_RUN)) {
		slen = m->m_len;
		clen = (*ttyp->sc_xcomp->compress)(ttyp->sc_xc_state, &mcomp, m, slen,
						   (ttyp->sc_flags & SC_CCP_UP ? if_mtu: 0), proto);
		if (mcomp != NULL) {
			ttyp->ifstats.bytes_saved += (slen - clen);
			m_free(m);
			m = mcomp;
			proto = PPP_COMP;
		}
	}
	
	if (!addr_field_comp[unit]) {
		stuff_char(ALLSTATIONS, unit, &out);    
		stuff_char(UI, unit, &out);
	}
	
	if (!proto_field_comp[unit] || proto >= 0xff)
		stuff_char(proto >> 8, unit, &out);
	stuff_char(proto & 0xff, unit, &out);
	
	for(i = 0; i < m->m_len; i++)
		stuff_char(*(m->m_data + i), unit, &out);
	add_fcs(&out, unit);
	*out.head++ = PPP_FLAG;
	
	m_free(m);
	
	return (out.head - out.buff);
}


/*
 * this is the output routine used by the link level protocols
 * it writes directly to the tty
 */
void
output(unit, p, len)
	int unit;
	u_char *p;
	int len;
{
#ifndef FULL_BOLT
        u_char outgoing[IF_OUTBUFFSIZE];
#endif
        int i;
	u_short proto;
	struct ppp_out out;
	struct ttys *ttyp;
	
	DEBUG_CALL("output (in ppp.c)");
	DEBUG_ARG("unit = %d", unit);
	DEBUG_ARG("p = %lx", (long)p);
	DEBUG_ARG("len = %d", len);
	
	ttyp = ttys_unit[unit];
	if (!ttyp)
	   return;
	
#ifndef FULL_BOLT
	out.buff = out.head = outgoing;
#else
	/* XXXXX Kludge */
	while ((len + ttyp->nbuff + 20 /* XXXXX */) > IF_OUTBUFFSIZE) {
		u_sleep(500);
		if_start(ttyp);
	}
	out.buff = out.head = ttyp->if_outbuff + ttyp->nbuff;
#endif
	
        out.fcs = PPP_FCS_INIT;
	*out.head++ = PPP_FLAG;
	
	proto = PPP_PROTOCOL(p);
	
	/*
	 * ppp_ccp expects no PPP header
	 */
	if (proto == PPP_CCP)
	   ppp_ccp(ttyp, p + PPP_HDRLEN, len, 0);
	
        for (i = 0; i <len; i++)
	   stuff_char(p[i], unit, &out);
        add_fcs(&out, unit);
        *out.head++ = PPP_FLAG;
	
#ifndef FULL_BOLT	
        writen(ttyp->fd, (char *) outgoing, (out.head - out.buff));
#else
	ttyp->nbuff += (out.head - out.buff);
	if_start(ttyp);
#endif
}

void
die(status)
	int status;
{
	slirp_exit(status);
}


/*
 *  we seem to be using PPP - initialise a few things
 */

void
ppp_init(ttyp)
	struct ttys *ttyp;
{
	int  i;
	
	/*
	 * Check if it's already been init'd
	 */
	if (ttyp->proto == PROTO_PPP)
	   return;
	
	for (i = 0; i < N_PROTO; i++)
	   (*prottbl[i].init)(ttyp->unit);
	
	check_auth_options(ttyp->unit);
	setipdefault(ttyp->unit);
	
	magic_init();
	ipcp_wantoptions[ttyp->unit].hisaddr = inet_addr(CTL_LOCAL);
	
	ttyp->proto = PROTO_PPP;
	ttyp->up = 0;
	ttyp->if_input = ppp_input;
	ttyp->if_encap = ppp_encap;
	ttyp->flags |= TTY_PPPSTART; /* Tell the main loop to call ppp_start on this ttyp */
}

/*
 * tell the user what options we are going to negotiate
 * and then start the negotiation process 
 */
void
ppp_start(unit)
	int unit;
{
	lcp_lowerup(unit);
	lcp_open(unit);
}

/* 
 * The following functions (random, srandom, index, bcmp, gethostid)
 * are defined here for systems that don't have them. The pppd pack-
 * age was written for BSD systems that have these non-ANSI funcs
 */

#ifndef HAVE_RANDOM
long
random ()
{
	return rand();
}
#endif

#ifndef HAVE_SRANDOM
void
srandom (seed)
	int seed;
{
	srand(seed);
}
#endif

#ifndef HAVE_INDEX
char *
index(s, c)
	const char *s;
	int c;
{
	return strchr(s, c);
}
#endif

#ifndef HAVE_BCMP
int
bcmp(s1, s2, n)
	const void *s1, *s2;
	int n;
{
	return memcmp(s1, s2, n);
}
#endif

#ifndef HAVE_GETHOSTID
long
gethostid()
{
	return 12345678;
}
#endif


/*
 * We define our own syslog, because we are not running as a
 * system daemon but a normal user program. This will raise
 * compile warning, because in some environments syslog is
 * defined to return int, and in some others it is void
 */

void
#ifdef __STDC__
real_do_syslog(int priority, const char *format, ...)
#else
real_do_syslog(va_alist) va_dcl
#endif
{
	va_list argp;

#ifdef __STDC__
	va_start(argp, format);
#else
	int priority;
	char *format;


	va_start(argp);
	priority = va_arg(argp, int);
	format = va_arg(argp, char *);
#endif
	vfprintf(logfile, format, argp);
	va_end(argp);
	fprintf(logfile, "\n");
	fflush(logfile);
}


/*
 * The rest of the functions are there just to satisfy
 * lcp.c, ipcp.c etc. They don't really do anything but
 * return an acceptable value
 */

int
sifaddr (unit, our_adr, his_adr, net_mask)
	int unit, our_adr, his_adr, net_mask;
{
        return 1;
}

int
cifaddr (unit, our_adr, his_adr)
	int unit, our_adr, his_adr;
{
        return 1;
}

int
sifdefaultroute (unit, gateway)
	int unit, gateway;
{
        return 1;
}

int
cifdefaultroute (unit, gateway)
	int unit, gateway;
{
        return 1;
}

#ifdef LOGWTMP_WORKED
/* I don't know why blocking this out solves so many problems with RedHat 6.
   But I'll do it anyway.  It doesn't do much of anything, and only ppp/auth.c
   called it to begin with. --Kelly */
int
logwtmp(line, name, host)
	char *line, *name, *host;
{
        return 1;
}
#endif /* I like these better than worrying about comment nesting. :P */

int
cifproxyarp (unit, his_adr)
	int unit;
	u_long his_adr;
{
        return 1;

}

int
sifproxyarp (unit, his_adr)
	int unit;
	u_long his_adr;
{
        return 1;
}


int
run_program(prog, args, must_exist)
	char *prog, **args;
	int must_exist;
{
        return 0;
}

void
print_string(p, len, printer, arg)
    char *p;
    int len;
    void (*printer) _P((void *, char *, ...));
    void *arg;
{

}


int
ccp_test(unit, ccp_option, opt_len, for_transmit)
	int unit;
	u_char *ccp_option;
	int opt_len, for_transmit;
{
	int nb;
	struct compressor **cp;
	struct ttys *ttyp = ttys_unit[unit];
	
	nb = opt_len;
	if (ccp_option[1] < 2)
	   return 0;
	for (cp = ppp_compressors; *cp != NULL; ++cp)
	   if ((*cp)->compress_proto == ccp_option[0]) {
		/*
		 * Found a handler for the protocol - try to allocate
		 * a compressor or decompressor.
		 */
		if (for_transmit) {
			if (ttyp->sc_xc_state != NULL)
			   (*ttyp->sc_xcomp->comp_free)(ttyp->sc_xc_state);
			ttyp->sc_xcomp = *cp;
			ttyp->sc_xc_state = (*cp)->comp_alloc(ccp_option, nb);
			if (ttyp->sc_xc_state == NULL)
			   return 0;
			ttyp->sc_flags &= ~SC_COMP_RUN;
		} else {
			if (ttyp->sc_rc_state != NULL)
			   (*ttyp->sc_rcomp->decomp_free)(ttyp->sc_rc_state);
			ttyp->sc_rcomp = *cp;
			ttyp->sc_rc_state = (*cp)->decomp_alloc(ccp_option, nb);
			if (ttyp->sc_rc_state == NULL)
			   return 0;
			ttyp->sc_flags &= ~SC_DECOMP_RUN;
		}
		return 1;
	}
	return 0;
}

void
ccp_flags_set(unit, isopen, isup)
    int unit, isopen, isup;
{
	struct ttys *ttyp = ttys_unit[unit];
	int x = ttyp->sc_flags;
	
	x = isopen? x | SC_CCP_OPEN: x &~ SC_CCP_OPEN;
	x = isup? x | SC_CCP_UP: x &~ SC_CCP_UP;
	
	ttyp->sc_flags = x;
}


int
ccp_fatal_error(unit)
	int unit;
{
	struct ttys *ttyp = ttys_unit[unit];
	
	return ttyp->sc_flags & SC_DC_FERROR;
}


/*
 * Handle a CCP packet.  rcvd' is 1 if the packet was received,
 * 0 if it is about to be transmitted.
 */
void
ppp_ccp(ttyp, dp, len, rcvd)
	struct ttys *ttyp;
	u_char *dp;
	int len;
	int rcvd;
{
	u_char *ep;
	int slen;
	
	ep = dp + len;
	if (dp + CCP_HDRLEN > ep)
	   return;
	slen = CCP_LENGTH(dp);
	if (dp + slen > ep)
	   return;
	
	switch (CCP_CODE(dp)) {
	 case CCP_CONFREQ:
	 case CCP_TERMREQ:
	 case CCP_TERMACK:
		/* CCP must be going down - disable compression */
		if (ttyp->sc_flags & SC_CCP_UP) {
			ttyp->sc_flags &= ~(SC_CCP_UP | SC_COMP_RUN | SC_DECOMP_RUN);
		}
		break;
		
	 case CCP_CONFACK:
		if (ttyp->sc_flags & SC_CCP_OPEN && !(ttyp->sc_flags & SC_CCP_UP)
		    && slen >= CCP_HDRLEN + CCP_OPT_MINLEN
		    && slen >= CCP_OPT_LENGTH(dp + CCP_HDRLEN) + CCP_HDRLEN) {
			
			if (!rcvd) {
				/* we're agreeing to send compressed packets. */
				if (ttyp->sc_xc_state != NULL
				    && (*ttyp->sc_xcomp->comp_init)
				    (ttyp->sc_xc_state, dp + CCP_HDRLEN, slen - CCP_HDRLEN,
				     ttyp->unit, 0, 0 /* XXX debug */)) {
					ttyp->sc_flags |= SC_COMP_RUN;
				}
			} else {
				/* peer is agreeing to send compressed packets. */
				if (ttyp->sc_rc_state != NULL
				    && (*ttyp->sc_rcomp->decomp_init)
				    (ttyp->sc_rc_state, dp + CCP_HDRLEN, slen - CCP_HDRLEN,
				     ttyp->unit, 0, if_mru,
				     0 /* XXX debug */)) {
					ttyp->sc_flags |= SC_DECOMP_RUN;
					ttyp->sc_flags &= ~(SC_DC_ERROR | SC_DC_FERROR);
				}
			}
		}
		break;
		
	 case CCP_RESETACK:
		if (ttyp->sc_flags & SC_CCP_UP) {
			if (!rcvd) {
				if (ttyp->sc_xc_state && (ttyp->sc_flags & SC_COMP_RUN))
				   (*ttyp->sc_xcomp->comp_reset)(ttyp->sc_xc_state);
			} else {
				if (ttyp->sc_rc_state && (ttyp->sc_flags & SC_DECOMP_RUN)) {
					(*ttyp->sc_rcomp->decomp_reset)(ttyp->sc_rc_state);
					ttyp->sc_flags &= ~SC_DC_ERROR;
				}
			}
		}
		break;
	}
}

/*
*  * CCP is down; free (de)compressor state if necessary.
*  */
void
ppp_ccp_closed(ttyp)
	struct ttys *ttyp;
{
	if (ttyp->sc_xc_state) {
		(*ttyp->sc_xcomp->comp_free)(ttyp->sc_xc_state);
		ttyp->sc_xc_state = NULL;
	}
	if (ttyp->sc_rc_state) {
		(*ttyp->sc_rcomp->decomp_free)(ttyp->sc_rc_state);
		ttyp->sc_rc_state = NULL;
	}
}
