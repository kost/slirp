void icmp_input _P((struct mbuf *, int));
void icmp_error _P((struct mbuf *, u_char, u_char, int, char *));
void icmp_reflect _P((struct mbuf *));
