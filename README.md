# slirp

Software program that emulates a PPP, SLIP, or CSLIP connection to the Internet via a shell account.

It is not actively maintained. Only for historic purposes.

## Cross compiling support

Example cross compile command using buildroot:

```
ac_cv_prog_gcc_traditional=no sr_cv_gethostid=yes sr_cv_declare_iovec=yes ac_cv_sizeof_char_p=4 ac_cv_sizeof_int=4 ac_cv_sizeof_short=2 ac_cv_sizeof_char=1 sr_cv_unix_sockets=no sr_cv_sprintf_declare=no sr_cv_sprintf_int=yes sr_cv_next=no ./configure --host=riscv32-linux
```

## Old Readme

HOWLS!!!  Thank you for pulling this latest release of Slirp.

The new maintainer for Slirp is Kelly "STrRedWolf" Price
The homepage is now http://slirp.sourceforge.net

Now, this is a new release with new numbering similar to the Linux kernel,
so if you see a x.even.x release, it's a stable release, while x.odd.x is a
developmental release.

Do read the README.NEXT file located here fully.  I(Kelly) am getting alot of
bug reports that don't have alot of stuff to go on.  Also contained in that
file is info on the mailing list.  Read it if you want to mess around with it,
there's alot to do inside!!!

One last thing.  For the arbitrary tty, set the enviroment varible SLIRP_TTY
to where you need to connect.  I use SLIRP_TTY=/dev/pilot slirp for my
Palm Pilot.

--Kelly


Update by Roger Plant

You can now use something like "tty /dev/ttyS0" on the command line to
set up an alternate tty.

For use under CYGWIN

You will need to supply a "dns YourDnsIP" option
slirp will not find it's DNS's under windows.
Alternatively you could possibly create and fill in a /etc/resolv.conf
file (Not tested...)

Modify the Makefile to have the -MS_DCC option enabled, It will allow a
direct cable connect into Slirp, PPP mode only. (This option works on
other platforms too, but is most likely to be useful for windows)

Also if it compiles, but doesn't work, try backing off the optimizer.
eg. -O1 instead of -O2, or even delete the option completely. This
applies to all platforms. Thanks Arnold Shulz


SECURITY

SLIRP remains insecure.

Most though not all of the buffer overflow issues indicated by Tim have
been addressed.

Slirp is a User program.

Anyone using slirp via a PPP connection, has or can obtain the
privileges that slirp is running at.



