FROM debian:wheezy
MAINTAINER ezPAARSE Team <ezpaarse@couperin.org>

ENV DEBIAN_FRONTEND noninteractive

RUN set -x \
  && apt-get -y update \
	&& apt-get -y install git curl python build-essential \
	&& apt-get -y upgrade \
	&& apt-get -y clean && rm -rf /var/lib/apt/lists/* \
	&& git clone https://github.com/ezpaarse-project/ezpaarse.git /root/ezpaarse \
	&& cd /root/ezpaarse && make

# tells jobs and logs folder is a volume cause lot of temporary data are written
# cf "when to use volumes"  http://www.projectatomic.io/docs/docker-image-author-guidance/
VOLUME /root/ezpaarse/tmp/jobs
VOLUME /root/ezpaarse/logs

ENV PATH /root/ezpaarse/build/nvm/bin/latest:/root/ezpaarse/bin:/root/ezpaarse/node_modules/.bin:$PATH

CMD ["ezpaarse", "start", "--no-daemon"]

EXPOSE 59599
