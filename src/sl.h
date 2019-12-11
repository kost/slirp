/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */

#define FRAME_END               0xc0            /* Frame End */
#define FRAME_ESCAPE            0xdb            /* Frame Esc */
#define TRANS_FRAME_END         0xdc            /* transposed frame end */
#define TRANS_FRAME_ESCAPE      0xdd            /* transposed frame esc */

extern int if_n;
extern struct mbuf if_fastq;
extern struct mbuf if_batchq;
extern int if_queued, if_thresh;

