FROM yottaiq/jok3r2.4
LABEL maintainer="yottaiq@gmail.com"
LABEL description="Docker Image for Jok3r - Network and Web Pentest Framework \
* Based on Parrot OS Linux, \
* All dependencies installed, \
* All tools in toolbox installed."

# Will not prompt for questions
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /root/jok3r

RUN git pull && ./install-all.sh
