FROM instrumentisto/nmap

COPY ./charly-script.sh /

RUN apk --update add git less openssh && \
    rm -rf /var/lib/apt/lists/* && \
    rm /var/cache/apk/*

RUN apk --no-cache --update --verbose add grep bash tcpdump && \
    rm -rf /var/cache/apk/* /tmp/* /sbin/halt /sbin/poweroff /sbin/reboot

WORKDIR /flightsim

ENTRYPOINT [ "sh" ]
CMD ["/charly-script.sh"]