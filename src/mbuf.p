void m_init _P((void));
void msize_init _P((void));
struct mbuf * m_get _P((void));
void m_free _P((struct mbuf *));
void m_cat _P((register struct mbuf *, register struct mbuf *));
void m_inc _P((struct mbuf *, int));
void m_adj _P((struct mbuf *, int));
int m_copy _P((struct mbuf *, struct mbuf *, int, int));
struct mbuf * dtom _P((void *));
