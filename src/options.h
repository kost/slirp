/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

struct cfgtab {
	char *command;
	char *command_line;
	int (*func) _P((char *, struct socket *));
	u_char type;
	u_char flags;
	char *usage_args;
	char *help;
};

#define CFG_CMD_FILE    PRN_STDERR      /* Can appear in config file or command line */
#define CFG_TELNET      PRN_SPRINTF
#define CFG_ANY         CFG_CMD_FILE|CFG_TELNET

#define CFG_NEEDARG     0x1

#define CFG_OK          0x0
#define CFG_BADARGS     0x1
#define CFG_ERROR       0x2     /* don't show usage on CFG_ERROR */

extern struct cfgtab cfg[];

extern int cfg_unit;
extern int cfg_quitting;

extern char *ctl_password;
extern int ctl_password_ok;

#endif
