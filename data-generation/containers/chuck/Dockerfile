FROM golang:1.15-alpine

COPY ./chuck-script.sh /

RUN apk --update add git less openssh && \
    rm -rf /var/lib/apt/lists/* && \
    rm /var/cache/apk/*

RUN apk --no-cache --update --verbose add grep bash tcpdump && \
    rm -rf /var/cache/apk/* /tmp/* /sbin/halt /sbin/poweroff /sbin/reboot

RUN mkdir /flightsim && cd /flightsim
RUN go get -u github.com/alphasoc/flightsim/

WORKDIR /flightsim

CMD ["sh", "/chuck-script.sh"]