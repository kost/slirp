int tcp_reass _P((register struct tcpcb *, register struct tcpiphdr *, struct mbuf *));
void tcp_input _P((register struct mbuf *, int, struct socket *));
void tcp_dooptions _P((struct tcpcb *, u_char *, int, struct tcpiphdr *));
void tcp_xmit_timer _P((register struct tcpcb *, int));
int tcp_mss _P((register struct tcpcb *, u_int));
