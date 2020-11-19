FROM mcr.microsoft.com/powershell:lts-centos-7

RUN yum install -y tcpdump net-tools iproute2

COPY simulate-traffic.ps1 ./
COPY bob-start.sh ./
COPY top500Domains.csv  ./

CMD ["sh", "bob-start.sh"]