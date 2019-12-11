void ifs_insque _P((struct mbuf *, struct mbuf *));
void ifs_remque _P((struct mbuf *));
void if_init _P((void));
inline int writen _P((int, char *, int));
void if_input _P((struct ttys *));
void if_output _P((struct socket *, struct mbuf *));
