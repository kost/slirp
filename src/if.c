/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>

extern int nozeros;

int if_mtu, if_mru;
int if_comp;
int if_maxlinkhdr;
int     if_queued = 0;                  /* Number of packets queued so far */
int     if_thresh = 10;                 /* Number of packets queued before we start sending
					 * (to prevent allocing too many mbufs) */

struct  mbuf if_fastq;                  /* fast queue (for interactive data) */
struct  mbuf if_batchq;                 /* queue for non-interactive data */
struct	mbuf *next_m;			/* Pointer to next mbuf to output */

#define ifs_init(ifm) ((ifm)->ifs_next = (ifm)->ifs_prev = (ifm))

void
ifs_insque(ifm, ifmhead)
	struct mbuf *ifm, *ifmhead;
{
	ifm->ifs_next = ifmhead->ifs_next;
	ifmhead->ifs_next = ifm;
	ifm->ifs_prev = ifmhead;
	ifm->ifs_next->ifs_prev = ifm;
}

void
ifs_remque(ifm)
	struct mbuf *ifm;
{
	ifm->ifs_prev->ifs_next = ifm->ifs_next;
	ifm->ifs_next->ifs_prev = ifm->ifs_prev;
}

void
if_init()
{
	/*
	 * Set if_maxlinkhdr to 48 because it's 40 bytes for TCP/IP,
	 * and 8 bytes for PPP, but need to have it on an 8byte boundary
	 */
#ifdef USE_PPP
	if_maxlinkhdr = 48;
#else
	if_maxlinkhdr = 40;
#endif
	if_mtu = 1500;
	if_mru = 1500;
	if_comp = IF_AUTOCOMP;
	if_fastq.ifq_next = if_fastq.ifq_prev = &if_fastq;
	if_batchq.ifq_next = if_batchq.ifq_prev = &if_batchq;
	sl_compress_init(&comp_s);
	next_m = &if_batchq;
}

/*
 * This shouldn't be needed since the modem is blocking and
 * we don't expect any signals, but what the hell..
 */
inline int
writen(fd, bptr, n)
	int fd;
	char *bptr;
	int n;
{
	int ret;
	int total;

    int x;
    for(x=0;x<n;x++)
    {
     DEBUG_MISC((dfd, "OUT: %c %02x\n", iscntrl(bptr[x] & 0xff) ? '.' : bptr[x] & 0xff, bptr[x] & 0xff));
    }


	/* This should succeed most of the time */
	ret = write(fd, bptr, n);
	if (ret == n || ret <= 0)
	   return ret;

	/* Didn't write everything, go into the loop */
	total = ret;
	while (n > total) {
		ret = write(fd, bptr+total, n-total);
		if (ret <= 0)
		   return ret;
		total += ret;
	}
	return total;
}

/*
 * if_input - read() the tty, do "top level" processing (ie: check for any escapes),
 * and pass onto (*ttyp->if_input)
 *
 * 0's and 1's arriving by themselves now ARE put into packet processing.
 * (But still will cause stop/detach)
 * Had problems with slow links, just losing 0's
 */

#define INBUFF_SIZE 2048 /* XXX */
void
if_input(ttyp)
	struct ttys *ttyp;
{
	u_char if_inbuff[INBUFF_SIZE];
	int if_n;

	DEBUG_CALL("if_input");
	DEBUG_ARG("ttyp = %lx", (long)ttyp);

	if_n = read(ttyp->fd, (char *)if_inbuff, INBUFF_SIZE);

	DEBUG_MISC((dfd, " read %d bytes, fd=%d\n", if_n, ttyp->fd));

	if (if_n <= 0) {
		if (if_n == 0 || (errno != EINTR && errno != EAGAIN)) {
			if (ttyp->up)
			   link_up--;
			tty_detached(ttyp, 0);
		}
		return;
	}


#if MS_DCC


    /*@@ Hack, should be elsewhere. Chat processing, handle MS DCC */

    if(ttyp->up)
        ttyp->dccpos=0;
    else {
        static char ring[]="CLIENT";
        static char answer[]="CLIENTSERVER";
        int idxPos;

        if(ttyp->dccpos < sizeof(ring) && if_n !=0) {
            for(idxPos=0;idxPos<if_n && ttyp->dccpos < sizeof(ring); idxPos++, ttyp->dccpos++)
            {
                if(if_inbuff[idxPos]!=ring[ttyp->dccpos])
                    ttyp->dccpos=0;
            }
            if(ttyp->dccpos >= sizeof(ring)-1) /* Seen ring send CLIENTSERVER back. */
                {
                DEBUG_MISC((dfd,"Got Ring\n"));
                write(ttyp->fd,answer, sizeof(answer)-1);
                }
        }
    }
#endif


#if DEBUG   /* Raw incoming data */
    if(if_n > 0)
        {
        int ax;
        for(ax=0;ax<if_n ;ax++)
            DEBUG_MISC((dfd, "IN: %c %02x\n", iscntrl(if_inbuff[ax] & 0xff) ? '.' : if_inbuff[ax], if_inbuff[ax] & 0xff));
        }
#endif

    if(!nozeros) {
        /* Catch 0's and 1's to exit */
    	if (if_n == 1) {
    		if (*if_inbuff == '0') {
    			ttyp->ones = 0;
    			if (++ttyp->zeros >= 5)
    			   slirp_exit(0);
    		} else if (*if_inbuff == '1') {
    			ttyp->zeros = 0;
    			if (++ttyp->ones >= 5)
                {
    			   tty_detached(ttyp, 0);
                   return;
                }
    		}
            else ttyp->ones = ttyp->zeros = 0;
    	}
        else
        	ttyp->ones = ttyp->zeros = 0;
    }
	(*ttyp->if_input)(ttyp, if_inbuff, if_n);
}


/*
 * if_output: Queue packet into an output queue.
 * There are 2 output queue's, if_fastq and if_batchq.
 * Each output queue is a doubly linked list of double linked lists
 * of mbufs, each list belonging to one "session" (socket).  This
 * way, we can output packets fairly by sending one packet from each
 * session, instead of all the packets from one session, then all packets
 * from the next session, etc.  Packets on the if_fastq get absolute
 * priority, but if one session hogs the link, it gets "downgraded"
 * to the batchq until it runs out of packets, then it'll return
 * to the fastq (eg. if the user does an ls -alR in a telnet session,
 * it'll temporarily get downgraded to the batchq)
 */
void
if_output(so, ifm)
	struct socket *so;
	struct mbuf *ifm;
{
	struct mbuf *ifq;
	int on_fastq = 1;
	
	DEBUG_CALL("if_output");
	DEBUG_ARG("so = %lx", (long)so);
	DEBUG_ARG("ifm = %lx", (long)ifm);
	
	/*
	 * First remove the mbuf from m_usedlist,
	 * since we're gonna use m_next and m_prev ourselves
	 * XXX Shouldn't need this, gotta change dtom() etc.
	 */
	if (ifm->m_flags & M_USEDLIST) {
		remque(ifm);
		ifm->m_flags &= ~M_USEDLIST;
	}
	
	/*
	 * See if there's already a batchq list for this session.  
	 * This can include an interactive session, which should go on fastq,
	 * but gets too greedy... hence it'll be downgraded from fastq to batchq.
	 * We mustn't put this packet back on the fastq (or we'll send it out of order)
	 * XXX add cache here?
	 */
	for (ifq = if_batchq.ifq_prev; ifq != &if_batchq; ifq = ifq->ifq_prev) {
		if (so == ifq->ifq_so) {
			/* A match! */
			ifm->ifq_so = so;
			ifs_insque(ifm, ifq->ifs_prev);
			goto diddit;
		}
	}
	
	/* No match, check which queue to put it on */
	if (so && (so->so_iptos & IPTOS_LOWDELAY)) {
		ifq = if_fastq.ifq_prev;
		on_fastq = 1;
		/*
		 * Check if this packet is a part of the last
		 * packet's session
		 */
		if (ifq->ifq_so == so) {
			ifm->ifq_so = so;
			ifs_insque(ifm, ifq->ifs_prev);
			goto diddit;
		}
	} else
		ifq = if_batchq.ifq_prev;
	
	/* Create a new doubly linked list for this session */
	ifm->ifq_so = so;
	ifs_init(ifm);
	insque(ifm, ifq);
	
diddit:
	++if_queued;
	
	if (so) {
		/* Update *_queued */
		so->so_queued++;
		so->so_nqueued++;
		/*
		 * Check if the interactive session should be downgraded to
		 * the batchq.  A session is downgraded if it has queued 6
		 * packets without pausing, and at least 3 of those packets
		 * have been sent over the link
		 * (XXX These are arbitrary numbers, probably not optimal..)
		 */
		if (on_fastq && ((so->so_nqueued >= 6) && 
				 (so->so_nqueued - so->so_queued) >= 3)) {
			
			/* Remove from current queue... */
			remque(ifm->ifs_next);
			
			/* ...And insert in the new.  That'll teach ya! */
			insque(ifm->ifs_next, &if_batchq);
		}
	}

#ifndef FULL_BOLT
	/*
	 * This prevents us from malloc()ing too many mbufs
	 */
	if (link_up) {
		/* if_start will check towrite */
		if_start();
	}
#endif
}

/*
 * Send a packet
 * We choose a packet based on it's position in the output queues;
 * If there are packets on the fastq, they are sent FIFO, before
 * everything else.  Otherwise we choose the first packet from the
 * batchq and send it.  the next packet chosen will be from the session
 * after this one, then the session after that one, and so on..  So,
 * for example, if there are 3 ftp session's fighting for bandwidth,
 * one packet will be sent from the first session, then one packet
 * from the second session, then one packet from the third, then back
 * to the first, etc. etc.
 */
#ifdef FULL_BOLT
void
if_start(ttyp)
	struct ttys *ttyp;
{
#else
void
if_start()
{
#endif
	struct mbuf *ifm, *ifqt;
	int n;
#ifndef FULL_BOLT
	struct ttys *ttyp;
	struct ttys *ttyp_best = ttys;
	char if_outbuff[2*2048+2]; /* XXX */
#endif
	struct ip *ip;
	u_int proto;
	
	DEBUG_CALL("if_start");
	
again:
#ifndef FULL_BOLT
	if (if_queued == 0)
	   return; /* Nothing to do */
	
	/*
	 * First, find the best modem to write to.. ie: the one with
	 * the greatest towrite
	 * We do this first so that if all the towrite's are < 0,
	 * we can bail early
	 */
	for (ttyp = ttys->next /* ttyp_best is already ttys */; ttyp; ttyp = ttyp->next) {
		if (!ttyp->up)
		   continue;
		if (ttyp->towrite == ttyp_best->towrite) {
			if (ttyp->bytesps > ttyp_best->bytesps)
			   ttyp_best = ttyp;
		} else if (ttyp->up && ttyp->towrite > ttyp_best->towrite) {
			ttyp_best = ttyp;
		}
	}
	
	/* If the greatest towrite is still < 0, bail */
	if (!ttyp_best->up || ttyp_best->towrite < 0)
	   return;
#else
	/*
	 * First write what was left over from last time
	 */
	if (ttyp->nbuff) {
		n = write(ttyp->fd, ttyp->if_outbuff+ttyp->nbuff_written,
					     ttyp->nbuff - ttyp->nbuff_written);
		DEBUG_ARG("wrote %lu bytes", (long)n);
		if (n <= 0)
		   return;
		ttyp->nbuff_written += n;
		if (ttyp->nbuff_written == ttyp->nbuff) {
			ttyp->nbuff = 0;
			ttyp->nbuff_written = 0;
		} else {
			return;
		}
	}
	
	if (if_queued == 0)
	   return; /* Nothing to do */
#endif
	
	/*
	 * See which queue to get next packet from
	 * If there's something in the fastq, select it immediately
	 */
	if (if_fastq.ifq_next != &if_fastq) {
		ifm = if_fastq.ifq_next;
	} else {
		/* Nothing on fastq, see if next_m is valid */
		if (next_m != &if_batchq)
		   ifm = next_m;
		else
		   ifm = if_batchq.ifq_next;
		
		/* Set which packet to send on next iteration */
		next_m = ifm->ifq_next;
	}
	/* Remove it from the queue */
	ifqt = ifm->ifq_prev;
	remque(ifm);
	--if_queued;
	
	/* If there are more packets for this session, re-queue them */
	if (ifm->ifs_next != /* ifm->ifs_prev != */ ifm) {
		insque(ifm->ifs_next, ifqt);
		ifs_remque(ifm);
	}
	
	/* Update so_queued */
	if (ifm->ifq_so) {
		if (--ifm->ifq_so->so_queued == 0)
		   /* If there's no more queued, reset nqueued */
		   ifm->ifq_so->so_nqueued = 0;
	}
	
	/* Compress, if needed */
	proto = TYPE_IP;
	if (if_comp & IF_COMPRESS) {
		ip = mtod(ifm, struct ip *);
		if (ip->ip_p == IPPROTO_TCP)
		   proto = sl_compress_tcp(ifm, ip, &comp_s, !(if_comp&IF_NOCIDCOMP));
	}
	
#ifndef FULL_BOLT
	/* Encapsulate the packet for sending */
	n = (*ttyp_best->if_encap)(if_outbuff, ifm, ttyp_best->unit,
				   (ttyp_best->towrite == towrite_max), proto);
	/* ifm is m_free()'d by if_encap */
	
	/* Send it */
	writen(ttyp_best->fd, if_outbuff, n);
	DEBUG_ARG("wrote %lu bytes", (long)n);
	ttyp_best->towrite -= n;
	ttyp_best->ifstats.out_pkts++;
	ttyp_best->ifstats.out_bytes += n;
	
	goto again;
#else
	/* Encapsulate the packet for sending */
	ttyp->nbuff = (*ttyp->if_encap)(ttyp->if_outbuff, ifm, ttyp->unit, 0, proto); /* XXXXX */
	ttyp->nbuff_written = write(ttyp->fd, ttyp->if_outbuff, ttyp->nbuff);
	if (ttyp->nbuff_written < 0) {
		ttyp->nbuff_written = 0;
		return;
	}
	if (ttyp->nbuff_written == ttyp->nbuff) {
		ttyp->nbuff = 0;
		ttyp->nbuff_written = 0;
	}
	
	if (if_queued)
	   goto again;
#endif
}
