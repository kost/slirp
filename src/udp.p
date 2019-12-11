void udp_init _P((void));
void udp_input _P((register struct mbuf *, int));
int udp_output _P((struct socket *, struct mbuf *, struct sockaddr_in *));
int udp_attach _P((struct socket *));
void udp_detach _P((struct socket *));
u_int8_t udp_tos _P((struct socket *));
void udp_emu _P((struct socket *, struct mbuf *));
struct socket * udp_listen _P((u_int, u_int32_t, u_int, int));
