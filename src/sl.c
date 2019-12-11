/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */

#include <slirp.h>

/* 
 * NOTE: FRAME_END means in_pkt = 0. Any other byte while in_pkt = 0
 * means we're getting a packet now.
 */
void
sl_input(ttyp, if_bptr, if_n)
	struct ttys *ttyp;
	u_char *if_bptr;
	int if_n;
{
	DEBUG_CALL("sl_input");
	DEBUG_ARG("ttyp = %lx", (long)ttyp);
	DEBUG_ARG("if_bptr = %lx", (long)if_bptr);
	DEBUG_ARG("if_n = %d", if_n);
	
	for (; if_n; if_bptr++, if_n--) {
		if (*if_bptr == FRAME_END) {
			if (ttyp->inpkt == 0)
			   continue;
			if (ttyp->esc) {
				ttyp->ifstats.in_mbad++;
				ttyp->mbad = 1;
			}
			if (!ttyp->mbad) {
				ttyp->m->m_len = (char *)ttyp->mptr - (char *)ttyp->m->m_data;
				sl_dispatch(ttyp);
			} else {
				m_free(ttyp->m);
				/* XXX */
			}
			ttyp->m = 0;
			ttyp->inpkt = 0;
			continue;
		}
		
		if (ttyp->inpkt == 0) {
			/* A new packet is arriving, setup mbufs etc. */
			ttyp->inpkt = 1;
			ttyp->m = m_get();
			ttyp->m->m_data += if_maxlinkhdr; /* Allow for uncompress */
			ttyp->mptr = mtod(ttyp->m, u_char *);
			ttyp->msize = M_FREEROOM(ttyp->m);
			ttyp->esc = 0;
			ttyp->mbad = 0;
		}
		
		if (!ttyp->mbad) {
			if (*if_bptr == FRAME_ESCAPE) {
				ttyp->esc = 1;
				/*
				 * Do the following in case the packet starts with FRAME_ESCAPE,
				 * which shouldn't happen, but...
				 */
				ttyp->inpkt = 1;
			} else {
				if (ttyp->esc) {
					switch (*if_bptr) {
					 case TRANS_FRAME_ESCAPE:
						*ttyp->mptr++ = FRAME_ESCAPE;
						break;
					 case TRANS_FRAME_END:
						*ttyp->mptr++ = FRAME_END;
						break;
					 default: /* XXX What to do? */
						*ttyp->mptr++ = *if_bptr;
					}
					ttyp->esc = 0;
				} else
					*ttyp->mptr ++ = *if_bptr;
				
				if (--ttyp->msize < 0) {
					ttyp->ifstats.in_mbad++;
					ttyp->mbad = 1;
				}
			}
		}
	}
}

void
sl_dispatch(ttyp)
	struct ttys *ttyp;
{
	u_char c;
	struct mbuf *m = ttyp->m;
	
	if ((c = (u_char)*m->m_data & 0xf0) != (IPVERSION << 4)) {
		if (c & 0x80)
		   c = TYPE_COMPRESSED_TCP;
		else if (c == TYPE_UNCOMPRESSED_TCP)
		   *m->m_data &= 0x4f; /* XXX */
		
		if (if_comp & IF_COMPRESS)
			m->m_len = sl_uncompress_tcp((u_char **)&m->m_data,
						     m->m_len,(u_int)c, &comp_s);
		else if ((if_comp & IF_AUTOCOMP) && c == TYPE_UNCOMPRESSED_TCP) {
			m->m_len = sl_uncompress_tcp((u_char **)&m->m_data,
						     m->m_len,(u_int)c, &comp_s);
			if (m->m_len > 0) {
				if_comp &= ~(IF_AUTOCOMP|IF_NOCOMPRESS);
				if_comp |= IF_COMPRESS;
			}
		}
		
		if (m->m_len > 0) {
			ttyp->ifstats.in_pkts++;
			ttyp->ifstats.in_bytes += m->m_len;
			ip_input(m);
		} else {
			ttyp->ifstats.in_errpkts++;
			ttyp->ifstats.in_errbytes += m->m_len;
			m_free(m);
		}
		
	} else {
		ttyp->ifstats.in_pkts++;
		ttyp->ifstats.in_bytes += m->m_len;
		ip_input(m);
	}
}



/*
 * Copy data from m to inbptr, applying SLIP encapsulation
 * Returns number of bytes in inbptr
 */
int
sl_encap(inbptr, m, unit, sl_esc, proto)
	char *inbptr;
	struct mbuf *m;
	int unit;
	int sl_esc;
	int proto;
{
	u_char *mptr;
	int mlen;
	char *bptr = inbptr;

	DEBUG_CALL("sl_encap");
	DEBUG_ARG("inbptr = %lx", (long)inbptr);
	DEBUG_ARG("m = %lx", (long)m);
	DEBUG_ARG("unit = %d", unit);
	DEBUG_ARG("sl_esc = %d", sl_esc);
	
	mptr = mtod(m, u_char *);
	*mptr |= proto; /* SLIP encodes the protocol in the first 4 bits */
	mlen = m->m_len;
	
	/*
	 * Prepend a FRAME_ESCAPE if no data is
	 * being sent, to flush any line-noise.
	 */
	if (sl_esc)
	   *bptr++ = FRAME_END;
	
	while(mlen--) {
		switch (*mptr) {
		 case FRAME_END:
			*bptr++ = FRAME_ESCAPE;
			*bptr++ = TRANS_FRAME_END;
			mptr++;
			break;
		 case FRAME_ESCAPE:
			*bptr++ = FRAME_ESCAPE;
			*bptr++ = TRANS_FRAME_ESCAPE;
			mptr++;
			break;
		 default:
			*bptr++ = *mptr++;
		}
	}
	*bptr++ = FRAME_END;
	
	m_free(m);
	
	return bptr - inbptr;
}
