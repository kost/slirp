/*
 * Copyright (c) 1995,1996 Danny Gasparovski.
 * Parts Copyright (c) 2000,2001 Kelly "STrRedWolf" Price.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#define WANT_SYS_IOCTL_H
#define WANT_TERMIOS_H
#include <slirp.h>
#include "main.h"

struct timeval tt;
struct ex_list *exec_list = NULL;

/* The patch broke slirp, but I think this will fix it.
 * I did a SLIRP_TTY=/dev/tty slirp and it actually worked.
 * So lets make it a default and change it all over to what the patch
 * does.
 *
 * Oh, yeah, Slirp likes to set a terminal to raw.  Grumble.
 * -RedWolf
 */
char *slirp_default_tty = "/dev/tty";  /* Ugly constant, but it works */
struct termios slirp_tty_settings; /* Half the world probably going to kill me. */
int slirp_tty_restore=0; /* Just incase we default to /dev/tty */

char *slirp_tty=NULL;  /* Make sure this is NULL */
extern int nozeros;


char *exec_shell;
char *socket_path;
int do_slowtimo;
int ctty_closed;

struct ttys *ttys;

extern void alrm _P((int));

struct in_addr our_addr;
struct in_addr ctl_addr;
struct in_addr special_addr;
struct in_addr dns_addr, dns2_addr;
struct in_addr loopback_addr;

int link_up;
int slirp_socket = -1;
int slirp_socket_unit = -1;
u_int32_t slirp_socket_addr;
int slirp_socket_port;
char *slirp_socket_passwd;
u_int slirp_socket_wait;
char *username;

int towrite_max = TOWRITEMAX;

#ifdef USE_PPP
char *path_upap;
char *path_chap;
#endif

FILE *lfd;

int
main(argc, argv)
	int argc;
	char **argv;
{

	lprint_print = (int (*) _P((void *, const char *, va_list)))vfprintf;
	lprint_ptr2 = (char *)stderr;
	lprint_arg = (char **)&lprint_ptr2;

	lprint("Slirp v%s (%s)\n\n", SLIRP_VERSION, SLIRP_STATUS);

	lprint("Copyright (c) 1995,1996 Danny Gasparovski and others.\n");
	lprint("All rights reserved.\n");
	lprint("This program is copyrighted, free software.\n");
	lprint("Please read the file COPYRIGHT that came with the Slirp\n");
	lprint("package for the terms and conditions of the copyright.\n\n");


    /* To enable debugging early, enable the following line,
       Do NOT use -d -1 on the command line in this case.
    */
    /* debug_init("slirp_debug", -1); */

	main_init(argc, argv);
	main_loop();
	/* NOTREACHED */
	return 0;
}

void
tty_init (argc, argv)
    int argc;
    char **argv;
{
     char* env_tty;
     size_t env_tty_len;


    /* @@Hack, first scan command line for a "tty /dev/ttyS0 type entry,
       make slirp_tty = that, otherwise use SLIRP_TTY environment.
       The options code will check that an argument is present for tty,
       but otherwise ignores it.
    */

    for(++argv;*argv;++argv)
    {
        if((strncmp(*argv, "tty", 3 ) == 0) && isspace((*argv)[3]))
        {
            /* Skip whitespace */
            char *ptr = (*argv)+3;
            while(isspace(*ptr) && *ptr)
                ptr++;

            if(*ptr)
                slirp_tty = strdup(ptr);

            break;
        }
     }

     if(slirp_tty == NULL) {

         env_tty = getenv ("SLIRP_TTY");
         if (NULL == env_tty) {
           /* We're using the terminal, so default to it.
            * While we're at it, save the terminal.
    	*/
           slirp_tty=NULL;  /* Assume nothing */

         } else {
           env_tty_len = strlen (env_tty);
           slirp_tty = malloc (env_tty_len + 1);
           if (NULL == slirp_tty) {
    	 lprint ("Error:  Out of memory allocating tty string.\r\n");
    	 slirp_exit (1);
           }

           strncpy2 (slirp_tty, env_tty, env_tty_len);
         }
     }
}

void
main_init(argc, argv)
     int argc;
     char **argv;
{
  int i;
  char buff[512];
  char *bptr;
#ifdef USE_PPP
  sigset_t mask;
  struct sigaction sa;
#endif

  tty_init(argc,argv);
  inet_aton("127.0.0.1", &loopback_addr);
  ctl_addr.s_addr = 0;
  special_addr.s_addr = -1;

#ifdef USE_TMPSOCKET
  /* Get user's name */
  username = getlogin();
  if (!username) {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
      username = pw->pw_name;
    if (!username) {
      lprint("Error: can't find your username\n");
      slirp_exit(1);
    }
  }
  strcpy(buff, "/tmp/");
  strncat(buff, username, sizeof(buff)-6);
  socket_path = strdup(buff);
#else
  if ((bptr = (char *)getenv("HOME")) == NULL) {
    lprint("Error: can't find your HOME\n");
    slirp_exit(1);
  }
  strncpy2(buff, bptr, sizeof(buff) - 15 );
  strcat(buff, "/.slirp_socket");
  socket_path = strdup(buff);
#endif

  /* XXX PPP init */
#ifdef USE_PPP
  if (gethostname(hostname, MAXNAMELEN) < 0 ) {
    perror("couldn't get hostname");
    die(1);
  }

  hostname[MAXNAMELEN-1] = 0;

  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  sa.sa_mask = mask;
  sa.sa_flags = 0;
  sa.sa_handler = alrm;
  sigaction(SIGALRM, &sa, NULL);
#endif
  /* Initialise everything */
/*
    Main aim of this seems to be to make debugging harder...

  for (i = 255; i > 2; i--) {
    close(i);
  }
*/

  /*
   * Check the socket
   */
  {
#ifndef NO_UNIX_SOCKETS
    struct sockaddr_un sock_un;
#endif
    struct sockaddr_in sock_in;
    int s = -1, unit, port = 0, ret;
    int want_link = 0;
    char pwd[256], hn[256];
    struct hostent *hp;

    /*
     * Check if the user wants to "attach" a new session
     */
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'l') {
      argv += 2; /* Point past -l N */
      argc -= 2;
      if (strchr(*argv, ':')) {

	/* It's an internet socket */
	if (sscanf(*argv, "%d,%[^:]:%d,%s", &unit, hn, &port, pwd) != 4) {
	  lprint("Error: bad arguments to -l\n");
	  slirp_exit(1);
	}
	if (strcmp(pwd, "-") == 0) {
	  /* It's in the environmental variable SLIRP_PASSWORD */
	  slirp_socket_passwd = (char *)getenv("SLIRP_PASSWORD");
	  if (slirp_socket_passwd == NULL) {
	    lprint("Error: no password in environmental variable SLIRP_PASSWORD\r\n");
	    slirp_exit(1);
	  }
	  slirp_socket_passwd = strdup(slirp_socket_passwd);
	} else {
	  slirp_socket_passwd = strdup(pwd);
	}

	if (!port) {
	  lprint("Error: bad port number\n");
	  slirp_exit(1);
	}

	if ((hp = gethostbyname(hn)) == NULL) {
	  lprint("Error: bad hostname\n");
	  slirp_exit(1);
	}
	slirp_socket_addr = *(u_int32_t *)hp->h_addr;

	/* Clear the password */
	memset(*argv, 'X', strlen(*argv));
      } else {
	unit = atoi(*argv);
      }
      want_link = 1;
    }
    slirp_socket_unit = unit;
    slirp_socket_port = port;

    ret = -1;
    if (slirp_socket_passwd) {
      s = socket(AF_INET, SOCK_STREAM, 0);
      if (s < 0) {
	perror("Error: Cannot create socket");
	slirp_exit(1);
      }
      sock_in.sin_family = AF_INET;
      sock_in.sin_addr.s_addr = slirp_socket_addr;
      sock_in.sin_port = htons(port);
      ret = connect(s, (struct sockaddr *)&sock_in, sizeof(sock_in));
    }
#ifndef NO_UNIX_SOCKETS
    else {
      s = socket(AF_UNIX, SOCK_STREAM, 0);
      if (s < 0) {
	perror("Error: Cannot create socket");
	slirp_exit(1);
      }
      sock_un.sun_family = AF_UNIX;

      strncpy2(sock_un.sun_path, socket_path, sizeof(sock_un.sun_path));
      sock_un.sun_path[sizeof(sock_un.sun_path)-1]='\0';

      ret = connect(s, (struct sockaddr *)&sock_un,
		    sizeof(sock_un.sun_family) + sizeof(sock_un.sun_path));
    }
#endif
    if (ret == 0) {
      /* Connected, we either link or die */
      if (!want_link) {
	/*
	 * Ooops, user doesn't want to attach another tty,
	 * but there's already a slirp running, quit.
	 */
	lprint("Error: Slirp is already running\n");
	slirp_exit(1);
      }

      /* Warn the user no more options are parsed */
      if (argc > 1)
	lprint("Warning: all options past -l are ignored\r\n");

      if (slirp_socket_passwd) {
	/* Internet connection */
	snprintf(buff, sizeof(buff), "%d %d %s", unit, 0, slirp_socket_passwd);
      }
#ifndef NO_UNIX_SOCKETS
      else {
	snprintf(buff, sizeof(buff), "%d %d %s", unit, (int)getpid(), ttyname(0));
      }
#endif
      write(s, buff, strlen(buff)+1);
      read(s, buff, 256);
      if (sscanf(buff, "%d %256[^\177]", &unit, buff) != 2) {
	lprint("Error: buff = %s\n", buff);
	slirp_exit(1);
      }
      if (unit) {
	/* Succeeded */
	lprint("Connected: %s\r\n", buff);
	if (slirp_socket_passwd)
	  relay(s);
	else
	  snooze();
      } else {
				/* Failed */
	lprint("Error:: %s\r\n", buff);
	slirp_exit(1);
      }

      close(s);
    } else {
      close(s);

      /* If we want a link, and it's not unit 0, bail... */
      if (want_link && unit != 0) {
	lprint("Error: cannot connect to Slirp socket\r\n");
	slirp_exit(1);
      }
    }
  }

  /*
   * Setup first modem
   */

  updtime();

  /* By this time, slirp_tty is NULL or is a string... */
  if (NULL == tty_attach (0, slirp_tty)) {
    lprint ("Error: tty_attach failed in main.c:main_init()\r\n");
    slirp_exit (1);
  }

  /* tty_attach in ttys.c takes care of this: ttys->fd = 0; */
  {
    struct stat stat;

    if (isatty(ttys->fd) && fstat(ttys->fd, &stat) == 0) {
      /* Save the current permissions */
      ttys->mode = stat.st_mode;
#ifdef HAVE_FCHMOD
      fchmod(ttys->fd, S_IRUSR|S_IWUSR);
#else
      chmod(ttyname(ttys->fd), S_IRUSR|S_IWUSR);
#endif
    }
  }
  ttys->flags |= TTY_CTTY;

  /* Initialise everything */
  /*	so_init(); */
  if_init();
  ip_init();

  getouraddr();

  if ((bptr = (char *)getenv("HOME")) != NULL) {
    strncpy2(buff, bptr, sizeof(buff)-11);
#ifdef USE_PPP
    path_upap=strjoin(buff, "/.pap-secrets");
    path_chap = strjoin(buff, "/.chap-secrets");

#endif
    strncat(buff, "/.slirprc", sizeof(buff));
    config(buff, ttys->unit);
  }
#ifdef USE_PPP
  else {
    path_upap = "/.pap-secrets";
    path_chap = "/.chap-secrets";
  }
#endif

  /* Parse options */
  cfg_unit = ttys->unit;
  while(--argc > 0) {
    int str_len;

    argv++;

    i = 0;
    do {
      if ((((str_len = strlen(cfg[i].command)) && !strncmp(*argv, cfg[i].command, str_len)) ||
	   (cfg[i].command_line && (str_len = strlen(cfg[i].command_line)) &&
	    !strncmp(*argv, cfg[i].command_line, str_len))) &&
	  (*(*argv+str_len) == ' ' || *(*argv+str_len) == '\t'
	   || *(*argv+str_len) == 0)) {
				/* Found it */
	while (*(*argv+str_len) == ' ' || *(*argv+str_len) == '\t')
	  str_len++;
	if (cfg[i].type & PRN_STDERR) {
	  if (**argv == '-' || **argv == '+') {
	    if (cfg[i].flags & CFG_NEEDARG) {
	      if (argc == 1) {
		lprint("Error: command \"%s\" requires an argument.\r\n",
		       cfg[i].command_line?cfg[i].command_line:cfg[i].command);
		break;
	      }
	      argv++;
	      argc--;
	      str_len = 0;
	    }
	  } else if ((cfg[i].flags & CFG_NEEDARG) && *(*argv+str_len) == 0) {
	    lprint("Error: Insufficient arguments to \"%s\".\r\n",
		   cfg[i].command);
	    break;
	  }
	  if ((*cfg[i].func)((*(*argv+str_len)?(*argv+str_len):(char *)0),
			     (struct socket *)0) == CFG_BADARGS)
	    lprint("Error: Usage %s %s\r\n", cfg[i].command, cfg[i].usage_args);
	  break;
	} else {
	  lprint("Error: Command can only be executed in telnet.\r\n");
	  break;
	}
      }
      i++;
    } while (cfg[i].command);

    if (!cfg[i].command)
      lprint("Error: Invalid option: %s\r\n", *argv);
  }

  if (special_addr.s_addr == -1)
    inet_aton(CTL_SPECIAL, &special_addr);

  if (our_addr.s_addr == 0) {
    lprint("Error:  Slirp Could not determine the address of this host.\r\n");
    lprint("        Some programs may not work without knowing this address.\r\n");
    lprint("        It is recommended you use the \"host address aaa.bbb.ccc.ddd\r\n\"");
    lprint("        option in your ~/.slirprc config file (where aaa.bbb.ccc.ddd\r\n");
    lprint("        is the IP address of the host Slirp is running on).\r\n\r\n");
  } else {
    lprint("IP address of Slirp host: %s\r\n", inet_ntoa(our_addr));
  }

  /* Print the DNS */
  {
    char buff[512];
    char buff2[256];
    FILE *f;
    int found = 0;
    struct in_addr tmp_addr;

    if(dns_addr.s_addr) /* Set up on command line perhaps. */
    {
        lprint("IP address of your DNS(s): %s", inet_ntoa(dns_addr));
        if(dns2_addr.s_addr)
            lprint(", %s", inet_ntoa(dns2_addr));
        lprint("\r\n");
    }
    else
    {
        if ((f = fopen("/etc/resolv.conf", "r")) != NULL) {
            lprint("IP address of your DNS(s): ");
            while (fgets(buff, 512, f) != NULL) {
    	if (sscanf(buff, "nameserver%*[ \t]%256s", buff2) == 1) {
            if (!inet_aton(buff2, &tmp_addr))
    	        continue;
    	    if (tmp_addr.s_addr == loopback_addr.s_addr)
    	        tmp_addr = our_addr;
    	  /* If it's the first one, set it to dns_addr */
    	  if (!found)
    	    dns_addr = tmp_addr;
    	  else {
    	    lprint(", ");
            if(!dns2_addr.s_addr)   /* Secondary dns */
              dns2_addr = tmp_addr;
          }

    	  if (++found > 3) {
    	    lprint("(more)");
    	    break;
    	  } else
    	    lprint("%s", inet_ntoa(tmp_addr));
    	  }
        }
      }
      if (found)
	lprint("\r\n");
      else {
       	lprint("[none found]\r\n");
       	dns_addr = our_addr; /* ??? */

      }
    }
  }

  lprint("Your address is %s\r\n", CTL_LOCAL);
  lprint("(or anything else you want)\r\n\r\n");

  if(!nozeros)
      lprint("Type five zeroes (0) to exit.\r\n\r\n");

  /* Setup exec_list */
  if (exec_shell) {
    add_exec(&exec_list, 1, exec_shell, CTL_EXEC, htons(23));
    free(exec_shell);
    exec_shell = 0;
  } else
    add_exec(&exec_list, 1, "/bin/sh", CTL_EXEC, htons(23));

  add_exec(&exec_list, 0, "slirp.ftpd", CTL_EXEC, htons(21));
#ifdef USE_PPP
  if(ttys->proto == PROTO_SLIP) {
#endif
    switch(if_comp) {
    case IF_COMPRESS:
      lprint("[talking CSLIP");
      break;
    case IF_AUTOCOMP:
      lprint("[autodetect SLIP/CSLIP");
      break;
    case IF_NOCOMPRESS:
      lprint("[talking SLIP");
      break;
    }
#ifndef FULL_BOLT
    lprint(", MTU %d, MRU %d, %d baud]\r\n\r\n", if_mtu, if_mru, ttys->baud);
#else
    lprint(", MTU %d, MRU %d]\r\n\r\n", if_mtu, if_mru);
#endif
#ifdef USE_PPP
  } else {
#ifndef FULL_BOLT
    lprint("[talking PPP, %d baud]\r\n\r\n", ttys->baud);
#else
    lprint("[talking PPP]\r\n\r\n");
#endif
  }
#endif

  lprint("SLiRP Ready ...\r\n");

  if (lfd) {
    fprintf(lfd, "End log.\n");
    fclose(lfd);
    lfd = 0;
  }

  /* Init a few things XXX */
  last_slowtimo = curtime;
  time_fasttimo = 0;

  /* Initialise mbufs *after* setting the MTU */
  m_init();

  /* Main_loop init */

  signal(SIGCHLD, do_wait);
  signal(SIGHUP, slirp_hup);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, slirp_exit);
  signal(SIGQUIT, slirp_exit);
  signal(SIGTERM, slirp_exit);

  /*	signal(SIGBUS, SIG_IGN); */

  /* clobber stdout and stderr so fprintf's don't clobber the link,

     **Updates**

     If stderr or stdout are not going to the same place as
     the ppp data will go too/come from (eg slirp_tty, or stdin)
     keep it open.

     Mainly for testing purposes, nice to be able to do fprintf(stderr...

     Includes Tim Watt's ttyname() fixes (modified)

  */

  {
  int blnKeepErr, blnKeepStdOut;
  const char *ttyname_0_dup = 0;
  const char *ttyname_1_dup = 0;
  const char *ttyname_2_dup = 0;

#define dup_ttyname(n) \
  if( (ttyname_##n##_dup = ttyname(n)) ) { \
    ttyname_##n##_dup = strdup(ttyname_##n##_dup); \
  }

#define clr_ttyname(n) \
  if( (ttyname_##n##_dup) ) { \
    free((char *) ttyname_##n##_dup); \
    ttyname_##n##_dup = 0; \
  }

  dup_ttyname(0)
  dup_ttyname(1)
  dup_ttyname(2)


  /* stderr going elsewhere ?? */
  blnKeepErr = FALSE;

  if(!isatty(2))
    blnKeepErr = TRUE;
  else {
    if((slirp_tty == NULL && ttyname_0_dup && ttyname_2_dup && strcmp(ttyname_0_dup, ttyname_2_dup) == 0) ||
       (slirp_tty != NULL && ttyname_2_dup && strcmp(ttyname_2_dup, slirp_tty) == 0) )
        blnKeepErr = FALSE;
    else
        blnKeepErr = TRUE;
    }

  /* stdout going elsewhere ?? */
  blnKeepStdOut = FALSE;
  if(!isatty(1))
    blnKeepStdOut = TRUE;
  else {
    if((slirp_tty == NULL && ttyname_0_dup && ttyname_1_dup && strcmp(ttyname_0_dup, ttyname_1_dup) == 0) ||
       (slirp_tty != NULL && ttyname_1_dup && strcmp(ttyname_1_dup, slirp_tty) == 0) )
        blnKeepStdOut = FALSE;
    else
        blnKeepStdOut = TRUE;
    }

  clr_ttyname(0);
  clr_ttyname(1);
  clr_ttyname(2);

#undef dup_ttyname
#undef clr_ttyname

  i = open("/dev/null", O_RDWR);

  if(!blnKeepStdOut)
    dup2(i, 1);
  if(!blnKeepErr)
    dup2(i, 2);
  if (i > 2)
    close(i);
  }

}


#define CONN_CANFSEND(so) (((so)->so_state & (SS_FCANTSENDMORE|SS_ISFCONNECTED)) == SS_ISFCONNECTED)
#define CONN_CANFRCV(so) (((so)->so_state & (SS_FCANTRCVMORE|SS_ISFCONNECTED)) == SS_ISFCONNECTED)
#define UPD_NFDS(x) if (nfds < (x)) nfds = (x)

fd_set writefds, readfds, xfds;

void
main_loop()
{
	struct socket *so, *so_next;
	struct timeval timeout;
	int ret, nfds;
	struct ttys *ttyp, *ttyp2;
#ifndef FULL_BOLT
	int best_time;
#endif
	int tmp_time;

while(1) {

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&xfds);
	nfds = 0;

	/*
	 * Always set modems for reading.
	 */
	link_up = 0;
	for (ttyp = ttys; ttyp; ttyp = ttyp->next) {
		if (ctty_closed && (ttyp->flags & TTY_CTTY)) {
			tty_detached(ttyp, 0);
			ctty_closed = 0;
			continue;
		}

		if (ttyp->up)
		   link_up++;
#ifdef USE_PPP
		else if (ttyp->flags & TTY_PPPSTART) {
			ppp_start(ttyp->unit);
			ttyp->flags &= ~TTY_PPPSTART;
		}
#endif

#ifdef FULL_BOLT
		if ((ttyp->up && if_queued) || ttyp->nbuff) {
			FD_SET(ttyp->fd, &writefds);
			UPD_NFDS(ttyp->fd);
		}
#endif
		FD_SET(ttyp->fd, &readfds);
		UPD_NFDS(ttyp->fd);
	}

	/*
	 * Set unix socket for reading if it exists
	 */
	if (slirp_socket >= 0) {
		if (!slirp_socket_wait || (curtime - slirp_socket_wait) >= 10000) {
			slirp_socket_wait = 0;
			FD_SET(slirp_socket, &readfds);
			UPD_NFDS(slirp_socket);
		}

		/*
		 * If there are no active tty's, make sure we don't
		 * hang around more than 10 minutes
		 */
		if (!ttys && ((curtime - detach_time) >= detach_wait))
		   slirp_exit(0);
	}

	/*
	 * First, TCP sockets
	 */
	do_slowtimo = 0;
	if (link_up) {
		/*
		 * *_slowtimo needs calling if there are IP fragments
		 * in the fragment queue, or there are TCP connections active
		 */
		do_slowtimo = ((tcb.so_next != &tcb) ||
			       ((struct ipasfrag *)&ipq != (struct ipasfrag *)ipq.next));

		for (so = tcb.so_next; so != &tcb; so = so_next) {
			so_next = so->so_next;

			/*
			 * See if we need a tcp_fasttimo
			 */
			if (time_fasttimo == 0 && so->so_tcpcb->t_flags & TF_DELACK)
			   time_fasttimo = curtime; /* Flag when we want a fasttimo */

			/*
			 * NOFDREF can include still connecting to local-host,
			 * newly socreated() sockets etc. Don't want to select these.
	 		 */
			if (so->so_state & SS_NOFDREF || so->s == -1)
			   continue;

			/*
			 * Set for reading sockets which are accepting
			 */
			if (so->so_state & SS_FACCEPTCONN) {
				FD_SET(so->s,&readfds);
				UPD_NFDS(so->s);
				continue;
			}

			/*
			 * Set for writing sockets which are connecting
			 */
			if (so->so_state & SS_ISFCONNECTING) {
				FD_SET(so->s,&writefds);
				UPD_NFDS(so->s);
				continue;
			}

			/*
			 * Set for writing if we are connected, can send more, and
			 * we have something to send
			 */
			if (CONN_CANFSEND(so) && so->so_rcv.sb_cc) {
				FD_SET(so->s, &writefds);
				UPD_NFDS(so->s);
			}

			/*
			 * Set for reading (and urgent data) if we are connected, can
			 * receive more, and we have room for it XXX /2 ?
			 */
			if (CONN_CANFRCV(so) && (so->so_snd.sb_cc < (so->so_snd.sb_datalen/2))) {
				FD_SET(so->s, &readfds);
				FD_SET(so->s, &xfds);
				UPD_NFDS(so->s);
			}
		}

		/*
		 * UDP sockets
		 */
		for (so = udb.so_next; so != &udb; so = so_next) {
			so_next = so->so_next;

			/*
			 * See if it's timed out
			 */
			if (so->so_expire) {
				if (so->so_expire <= curtime) {
					udp_detach(so);
					continue;
				} else
					do_slowtimo = 1; /* Let socket expire */
			}

			/*
			 * When UDP packets are received from over the
			 * link, they're sendto()'d straight away, so
			 * no need for setting for writing
			 * Limit the number of packets queued by this session
			 * to 4.  Note that even though we try and limit this
			 * to 4 packets, the session could have more queued
			 * if the packets needed to be fragmented
			 * (XXX <= 4 ?)
			 */
			if ((so->so_state & SS_ISFCONNECTED) && so->so_queued <= 4) {
				FD_SET(so->s, &readfds);
				UPD_NFDS(so->s);
			}
		}
	}

	/*
	 * Setup timeout to use minimum CPU usage, especially when idle
	 */

	/*
	 * First, see the timeout needed by *timo
	 */
	timeout.tv_sec = 0;
	timeout.tv_usec = -1;
	/*
	 * If a slowtimo is needed, set timeout to 500ms from the last
	 * slow timeout. If a fast timeout is needed, set timeout within
	 * 200ms of when it was requested.
	 */
	if (do_slowtimo) {
		/* XXX + 10000 because some select()'s aren't that accurate */
		timeout.tv_usec = ((500 - (curtime - last_slowtimo)) * 1000) + 10000;
		if (timeout.tv_usec < 0)
		   timeout.tv_usec = 0;
		else if (timeout.tv_usec > 510000)
		   timeout.tv_usec = 510000;

		/* Can only fasttimo if we also slowtimo */
		if (time_fasttimo) {
			tmp_time = (200 - (curtime - time_fasttimo)) * 1000;
			if (tmp_time < 0)
			   tmp_time = 0;

			/* Choose the smallest of the 2 */
			if (tmp_time < timeout.tv_usec)
			   timeout.tv_usec = (u_int)tmp_time;
		}
	}

#ifndef FULL_BOLT
	/*
	 * Find the timeout such that we can then write to a modem
	 */
	if (!if_queued || !link_up)
		tmp_time = -1; /* Nothing to do, flag to block forever */
	else {
		best_time = 500001;
		for (ttyp = ttys; ttyp; ttyp = ttyp->next) {
			if (!ttyp->up)
			   continue;
			/*
			 * If there's a modem which we can write to now,
			 * set the timeout to 0 (although it will be adjusted later on)
			 */
			if (ttyp->towrite >= 0) {
				best_time = 0;
				/*
				 * If this modem hasn't been busy lately
			 	 * (ie: it has a maximum towrite (XXX? towrite_max/2?))
			 	 * then we *really* have a timeout of 0, instead of an adjusted one
				 */
				if (ttyp->towrite == towrite_max)
				   goto cont_1;
			} else {
				if (best_time) {
					tmp_time = (((-ttyp->towrite + 1) * 1000000) / ttyp->bytesps);
					if (tmp_time < best_time)
					   best_time = tmp_time;
				}
			}
		}

		/*
		 * Adjust the timeout to make the minimum timeout
		 * 50ms (XXX?) to lessen the CPU load
		 */
		if (best_time > 500000)
		   best_time = 500000;
		else if (best_time < 50000) /* XXX */
		   best_time = 50000;
cont_1:
		tmp_time = best_time;
	}
	/*
	 * Take the minimum of the above calculated timeouts
	 */
	if ((timeout.tv_usec < 0) || (tmp_time >= 0 && tmp_time < timeout.tv_usec))
		timeout.tv_usec = (u_int)tmp_time;
#endif
	DEBUG_MISC((dfd, " timeout.tv_usec = %u",
		    (u_int)timeout.tv_usec));
	if (time_fasttimo) {
		DEBUG_MISC((dfd, ", need fasttimo\n"));
	} else {
		DEBUG_MISC((dfd, "\n"));
	}

	/*
	 * Do the real select call
	 */

	/*
	 * If we're told to "wait forever", wait for 5 seconds
	 * This will make timings (like idle timer and "wait" timer)
	 * up to 10 seconds late, but will be more system friendly
	 */
	if (timeout.tv_usec == -1) {
		timeout.tv_usec = 0;
		timeout.tv_sec = 5; /* XXX */
	}

	ret = select(nfds+1, &readfds, &writefds, &xfds, &timeout);

	if (ret < 0) {
		if (errno == EINTR)
		   continue;
		slirp_exit(1);
	}

	/* Update time */
	updtime();

	/*
	 * See if anything has timed out
	 */
	if (link_up) {
		if (time_fasttimo && ((curtime - time_fasttimo) >= 199)) {
			tcp_fasttimo();
			time_fasttimo = 0;
		}
		if (do_slowtimo && ((curtime - last_slowtimo) >= 499)) {
			ip_slowtimo();
			tcp_slowtimo();
			last_slowtimo = curtime;
		}
	}

	/*
	 * Check if there are any tty's attaching
	 */
	if (slirp_socket >= 0 && FD_ISSET(slirp_socket, &readfds)) {
		int fd, unit, pid=0;
		char buff[512];
		char buff2[256];
		char dev[256];
		char *device = dev;
#ifndef NO_UNIX_SOCKETS
		struct sockaddr_un sock_un;
		socklen_t sock_len = sizeof(struct sockaddr_un);
#endif
		struct sockaddr_in sock_in;
		socklen_t sock_len2 = sizeof(struct sockaddr_in);

		fd = -1;
		if (slirp_socket_passwd)
		   fd = accept(slirp_socket, (struct sockaddr *)&sock_in, &sock_len2);
#ifndef NO_UNIX_SOCKETS
		else
		   fd = accept(slirp_socket, (struct sockaddr *)&sock_un, &sock_len);
#endif
		if (fd < 0) {
			/*
			 * This shouldn't happen, but if it does, something's
			 * amiss, so we nuke the socket so that we don't enter
	 		 * a tight loop of failure to accept() the socket
             *
			 */
       		slirp_socket = -1;
		    goto failed;
		}

		/*
		 * Some maniac could telnet to this port and stall Slirp forever.
		 * So, we make the socket non-blocking and wait a second.  If the message
		 * hasn't arrived, we wait another seconds and try again.  If it still
		 * hasn't arrived, we nuke the connection and don't let them connect back
		 * for another 10 seconds
		 *
		 * Infact, whenever it fails we don't allow another connect for 10 seconds,
		 * again to stop some joker from writing a program to keep connecting to this
		 * socket in a tight loop
		 */
		fd_nonblock(fd);
		if (read(fd, buff, 256) < 0) {
			sleep(1);
			if (read(fd, buff, 256) < 0) {
				/* Nuke both connections */
				snprintf(buff, sizeof(buff), "0 Connection timed out");
				write(fd, buff, strlen(buff)+1);
				slirp_socket_wait = curtime;
				close(fd);
				goto failed;
			}
		}
		/* XXX Make it blocking again? */
		fd_block(fd);

		if (sscanf(buff, "%d %d %256s", &unit, &pid, device) == 3) {
			if (unit >= MAX_INTERFACES || unit < 0) {
				snprintf(buff, sizeof(buff), "0 Unit out of range (must be between 0 and %d, inclusive)", MAX_INTERFACES-1);
				write(fd, buff, strlen(buff)+1);
				slirp_socket_wait = curtime;
				close(fd);
				goto failed;
			}

			/* Socket is an internet socket and the device is the password
			 * (pid is invalid) */
			if (slirp_socket_passwd) {
				if (strcmp(slirp_socket_passwd, device) != 0) {
					snprintf(buff, sizeof(buff), "0 Incorrect password");
					write(fd, buff, strlen(buff)+1);
					slirp_socket_wait = curtime;
					close(fd);
					goto failed;
				} else {
					device = 0; /* Make tty_attach not open a device */
				}
			}

			/*
			 * Check that unit is not already taken,
			 * and it's valid
			 */
			for (ttyp = ttys; ttyp; ttyp = ttyp->next) {
				if (ttyp->unit == unit)
				   break;
			}

			/*
			 * Reply is of the form "<N> <MESSAGE>" where N is 0 for
			 * failure, 1 for exit, and message is printed
			 */
			if (ttyp) {
				snprintf(buff, sizeof(buff), "0 Unit already attached");
				write(fd, buff, strlen(buff)+1);
				slirp_socket_wait = curtime;
				close(fd);
				goto failed;
			}

			ttyp = tty_attach(unit, device);
			if (ttyp) {
#ifdef USE_PPP
				if (ttyp->proto == PROTO_PPP)
				   strcpy(buff2, "PPP");
				else
#endif
				   snprintf(buff2, sizeof(buff2), "SLIP, MTU %d, MRU %d", if_mtu, if_mru);
#ifndef FULL_BOLT
				snprintf(buff, sizeof(buff),
					"1 Attached as unit %d, device %s\r\n\r\n[talking %s, %d baud]\r\n\r\nSLiRP Ready ...",
					unit, device?device:"(socket)", buff2, ttyp->baud);
#else
                               snprintf(buff, sizeof(buff),
					"1 Attached as unit %d, device %s\r\n\r\n[talking %s]\r\n\r\nSLiRP Ready ...",
					unit, device, buff2);
#endif
				write(fd, buff, strlen(buff)+1);
				if (!slirp_socket_passwd) {
					close(fd);
				}

				ttyp->pid = pid;
				if (slirp_socket_passwd) {
					/* Internet socket, don't close fd */
					ttyp->fd = fd;
				}
			} else {
				snprintf(buff, sizeof(buff), "0 %s", strerror(errno));
				write(fd, buff, strlen(buff)+1);
				slirp_socket_wait = curtime;
				close(fd);
				goto failed;
			}

		} else if (sscanf(buff, "kill %[^:]:%d", device, &unit) == 2) {
			if (slirp_socket_passwd) {
				if (strcmp(slirp_socket_passwd, device) != 0) {
					slirp_socket_wait = curtime;
					close(fd);
					goto failed;
				}
			}

			for (ttyp = ttys; ttyp; ttyp = ttyp->next) {
				if (ttyp->unit == unit) {
					tty_detached(ttyp, 0);
					continue;
				}
			}
			close(fd);
		} else {
			/* Ooops, close the socket and don't accept
			 * another connection for 10 seconds */
			slirp_socket_wait = curtime;
			close(fd);
		}
	}
failed:

	/*
	 * Check if a tty is ready for reading [or writing]
	 */
	for (ttyp = ttys; ttyp; ttyp = ttyp2) {
        ttyp2 = ttyp->next;     /* Just in case if_input removes it from under us */
        DEBUG_ARG("hunting ttyp=%lx", (long) ttyp);

		if (FD_ISSET(ttyp->fd, &readfds))
		   if_input(ttyp);
#ifdef FULL_BOLT
		if (FD_ISSET(ttyp->fd, &writefds))
		   if_start(ttyp);
#endif
        /* ttyp may not be valid here, if_input() may have had it deleted... */

	}
	
	/*
	 * Check sockets
	 */
	if (link_up) {
		/*
		 * Check TCP sockets
		 */
		for (so = tcb.so_next; so != &tcb; so = so_next) {
			so_next = so->so_next;
			
			/*
			 * FD_ISSET is meaningless on these sockets
			 * (and they can crash the program)
			 */
			if (so->so_state & SS_NOFDREF || so->s == -1)
			   continue;
			
			/*
			 * Check for URG data
			 * This will soread as well, so no need to
			 * test for readfds below if this succeeds
			 */
			if (FD_ISSET(so->s, &xfds))
			   sorecvoob(so);
			/*
			 * Check sockets for reading
			 */
			else if (FD_ISSET(so->s, &readfds)) {
				/*
				 * Check for incoming connections
				 */
				if (so->so_state & SS_FACCEPTCONN) {
					tcp_connect(so);
					continue;
				} /* else */
				ret = soread(so);
				
				/* Output it if we read something */
				if (ret > 0)
				   tcp_output(sototcpcb(so));
			}
			
			/*
			 * Check sockets for writing
			 */
			if (FD_ISSET(so->s,&writefds)) {
			  /*
			   * Check for non-blocking, still-connecting sockets
			   */
			  if (so->so_state & SS_ISFCONNECTING) {
			    /* Connected */
			    so->so_state &= ~SS_ISFCONNECTING;
			    
			    ret = write(so->s, &ret, 0);
			    if (ret < 0) {
			      /* XXXXX Must fix, zero bytes is a NOP */
			      if (errno == EAGAIN || errno == EWOULDBLOCK ||
				  errno == EINPROGRESS || errno == ENOTCONN)
				continue;
			      
			      /* else failed */
			      so->so_state = SS_NOFDREF;
			    }
			    /* else so->so_state &= ~SS_ISFCONNECTING; */
			    
			    /*
			     * Continue tcp_input
			     */
			    tcp_input((struct mbuf *)NULL, sizeof(struct ip), so);
			    /* continue; */
			  } else
			    ret = sowrite(so);
			  /*
			   * XXXXX If we wrote something (a lot), there 
			   * could be a need for a window update.
			   * In the worst case, the remote will send
			   * a window probe to get things going again
			   */
			}
			
			/*
			 * Probe a still-connecting, non-blocking socket
			 * to check if it's still alive
	 	 	 */
#ifdef PROBE_CONN
			if (so->so_state & SS_ISFCONNECTING) {
			  ret = read(so->s, (char *)&ret, 0);
			  
			  if (ret < 0) {
			    /* XXX */
			    if (errno == EAGAIN || errno == EWOULDBLOCK ||
				errno == EINPROGRESS || errno == ENOTCONN)
			      continue; /* Still connecting, continue */
			    
			    /* else failed */
			    so->so_state = SS_NOFDREF;
			    
			    /* tcp_input will take care of it */
			  } else {
			    ret = write(so->s, &ret, 0);
			    if (ret < 0) {
			      /* XXX */
			      if (errno == EAGAIN || errno == EWOULDBLOCK ||
				  errno == EINPROGRESS || errno == ENOTCONN)
				continue;
			      /* else failed */
			      so->so_state = SS_NOFDREF;
			    } else
			      so->so_state &= ~SS_ISFCONNECTING;
			    
			  }
			  tcp_input((struct mbuf *)NULL, sizeof(struct ip),so);
			} /* SS_ISFCONNECTING */
#endif
		}
		
		/*
		 * Now UDP sockets.
		 * Incoming packets are sent straight away, they're not buffered.
		 * Incoming UDP data isn't buffered either.
		 */
		for (so = udb.so_next; so != &udb; so = so_next) {
			so_next = so->so_next;
			
			if (so->s != -1 && FD_ISSET(so->s,&readfds))
			   sorecvfrom(so);
		}
	}
	
#ifndef FULL_BOLT
	/*
	 * See if we can start outputting
	 */
	if (if_queued && link_up)
	   if_start();
#endif
	
} /* while(1) { */
}

void
do_wait(n)
	int n;
{
	int stat;
#ifndef WNOHANG
/* XXXXX YUCK! but it's the only solution I was given for OSF/1 */
#define WNOHANG 0x1
#endif	
	while (waitpid((pid_t)-1, &stat, WNOHANG) > 0)
	   ; /* do nothing */
	signal(SIGCHLD, do_wait);
}

/*
 * curtime kept to an accuracy of 1ms
 */
void
updtime()
{
#ifndef FULL_BOLT
	u_int inc;
	struct ttys *ttyp;
	static u_int towrite_lastime;
#endif
	
	gettimeofday(&tt, 0);
	
	curtime = (u_int)tt.tv_sec * (u_int)1000;
	curtime += (u_int)tt.tv_usec / (u_int)1000;
	
	if ((tt.tv_usec % 1000) >= 500)
	   curtime++;

#ifndef FULL_BOLT
	/*
	 * Update towrite on if either
	 *   a) all modems have towrite < 0; or
	 *   b) it's been 1 second since the last time it was updated
         * The reson is that if there's lots of UDP packets for example,
	 * and the user uses an unusually high baudrate (as most do),
	 * each call to updtime() will completely restore the tty's towrite
         * hence the next packet will go over the same modem again
         * (this won't happen with TCP because it sends data in 4k chunks,
	 * so updtime() won't be called in between each packet)
	 */
	if ((curtime - towrite_lastime) < 1000) {
		for (ttyp = ttys; ttyp; ttyp = ttyp->next) {
			if (ttyp->towrite >= 0)
			   return;
		}
	}
	
	/* Update all towrite's */
	towrite_lastime = curtime;
	
	for (ttyp = ttys; ttyp; ttyp = ttyp->next) {
		inc = (((curtime - ttyp->lastime) *  ttyp->bytesps) / 1000);
		
		if (inc > 0) {
			ttyp->lastime = curtime;
			ttyp->towrite += inc;
			if (ttyp->towrite > towrite_max)
			   ttyp->towrite = towrite_max;
		}
	}
#endif
}

void
slirp_hup(num)
	int num;
{
	ctty_closed = 1;
	signal(SIGHUP, SIG_IGN); /* XXX */
}
