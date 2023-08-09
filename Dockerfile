FROM ubuntu

RUN apt update -y && apt install -y ca-certificates

COPY ./id-proxy /root/id-proxy
CMD /root/id-proxy
