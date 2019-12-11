void tcp_fasttimo _P((void));
void tcp_slowtimo _P((void));
void tcp_canceltimers _P((struct tcpcb *));
struct tcpcb * tcp_timers _P((register struct tcpcb *, int));
