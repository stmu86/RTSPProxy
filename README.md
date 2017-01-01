# RTSPProxy
Rewrites destination ip address in RTSP SETUP request

compile with gcc -o rtspproxy rtspproxy.c

thanks TPROXY EXAMPLE for helping. (https://github.com/kristrev/tproxy-example)

please see https://www.kernel.org/doc/Documentation/networking/tproxy.txt to get it work

TODO:

-use select() to make read / writes on sockets better

-signaling, errorhandling, fork() multiconnections, connection handling........

last changes:

add --debug for console output

fork to deaemon

add syslog

add teardown

