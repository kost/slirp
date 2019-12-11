void sbfree _P((struct sbuf *));
void sbdrop _P((struct sbuf *, int));
void sbreserve _P((struct sbuf *, int));
void sbappend _P((struct socket *, struct mbuf *));
void sbappendsb _P((struct sbuf *, struct mbuf *));
void sbcopy _P((struct sbuf *, int, int, char *));
