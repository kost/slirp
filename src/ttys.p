struct ttys * tty_attach _P((int, char *));
void tty_detached _P((struct ttys *, int));
void ctty_detached _P((void));
