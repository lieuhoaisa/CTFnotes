FROM ubuntu:20.04@sha256:a0d9e826ab87bd665cfc640598a871b748b4b70a01a4f3d174d4fb02adad07a9
#FROM ubuntu:20.04

RUN apt update
RUN apt-get install -y socat

RUN adduser pwn

COPY ./flag /flag
COPY ./prob /prob
COPY ./libc-2.31.so /libc.so.6
RUN chmod 755 /flag /prob


RUN export LD_PRELOAD='/libc.so.6' 

USER pwn
EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:/prob
