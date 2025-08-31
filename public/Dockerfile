FROM debian:bookworm

RUN apt update -y && apt upgrade -y && apt install -y build-essential wget cmake && apt-get install -y cron


############### INSTALL FNETD
RUN wget https://cloud.sec.in.tum.de/index.php/s/65BwEo2zgLFGa65/download/fnetd.tar.xz -O /fnetd.tar.xz
RUN tar -xf fnetd.tar.xz
RUN mkdir /fnetd/build

WORKDIR /fnetd/build
RUN cmake .. -G "Unix Makefiles"
RUN make

WORKDIR /
############### END INSTALL

#ADD REAL get_flag BINARY HERE
#COPY get_flag /bin/get_flag

# Uncomment to use course libc.
COPY libc-2.36.so /lib/x86_64-linux-gnu/libc-2.36-bx.so 
RUN ln -sf /lib/x86_64-linux-gnu/libc-2.36-bx.so /lib/x86_64-linux-gnu/libc.so.6

RUN useradd -m pwn

COPY vuln /home/pwn/vuln

RUN chmod 0755 /home/pwn/vuln

EXPOSE 1337

#Create our dedicated logfolder
RUN mkdir /tmp/sLogs
RUN chmod 777 /tmp/sLogs
#Setup a cronjob to remove logs at the beginning of every hour
RUN (crontab -l ; echo "0 * * * * rm -rf /tmp/sLogs/* > /proc/1/fd/1 2>/proc/1/fd/2") | crontab
#Uncomment this line to increase the rate at which logs are purged to once every minute
#RUN (crontab -l ; echo "* * * * * rm -rf /tmp/sLogs/* > /proc/1/fd/1 2>/proc/1/fd/2") | crontab
#Copy Startupscript
COPY start.sh /start.sh
RUN chmod +x /start.sh

#CHANGE PASSWORD
ENV FNETD_PASSWORD=fnetd_password
CMD ["/start.sh"]
