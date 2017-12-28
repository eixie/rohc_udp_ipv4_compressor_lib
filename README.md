
Simple ROHC compress library(RFC3095) dedicated for udp/ipv4 unidirectional mode (profile=0x0002)

For IP dynamic context, it supports SID field extension
For IP dynamic context, it does not support reserved octect, i.e. IP dynamic context only has: TTL/TOS/IP_ID/SID-RND-NBO-DF

The library is built under msys2 environment under windows7 X64, and it is easy to build on other platforms by modifing the makefile.

