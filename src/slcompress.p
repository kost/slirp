void sl_compress_init _P((struct slcompress *));
u_int sl_compress_tcp _P((struct mbuf *, register struct ip *, struct slcompress *, int));
int sl_uncompress_tcp _P((u_char **, int, u_int, struct slcompress *));
