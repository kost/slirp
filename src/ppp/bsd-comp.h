/*
 * A dictionary for doing BSD compress.
 */
struct bsd_db {
	int     totlen;                     /* length of this structure */
	u_int   hsize;                      /* size of the hash table */
	u_char  hshift;                     /* used in hash function */
	u_char  n_bits;                     /* current bits/code */
	u_char  maxbits;
	u_char  debug;
	u_char  unit;
	u_int16_t seqno;                      /* sequence # of next packet */
	u_int   hdrlen;                     /* header length to preallocate */
	u_int   mru;
	u_int   maxmaxcode;                 /* largest valid code */
	u_int   max_ent;                    /* largest code in use */
	u_int   in_count;                   /* uncompressed bytes, aged */
	u_int   bytes_out;                  /* compressed bytes, aged */
	u_int   ratio;                      /* recent compression ratio */
	u_int   checkpoint;                 /* when to next check the ratio */
	u_int   clear_count;                /* times dictionary cleared */
	u_int   incomp_count;               /* incompressible packets */
	u_int   incomp_bytes;               /* incompressible bytes */
	u_int   uncomp_count;               /* uncompressed packets */
	u_int   uncomp_bytes;               /* uncompressed bytes */
	u_int   comp_count;                 /* compressed packets */
	u_int   comp_bytes;                 /* compressed bytes */
	u_int16_t *lens;                      /* array of lengths of codes */
	struct bsd_dict {
		union {
			/* hash value */
			u_int32_t   fcode;
			struct {
#ifdef WORDS_BIGENDIAN
				u_char  pad;
				u_char  suffix;         /* last character of new code */
				u_int16_t prefix;         /* preceding code */
#else
				u_int16_t prefix;         /* preceding code */
				u_char  suffix;         /* last character of new code */
				u_char  pad;
#endif
			} hs;
		} f;
		u_int16_t codem1;                 /* output of hash table -1 */
		u_int16_t cptr;                   /* map code to hash table entry */
	} dict[1];
};

