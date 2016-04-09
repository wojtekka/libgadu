FROM ubuntu:trusty

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		git ca-certificates \
		protobuf-c-compiler autoconf automake libtool gcc make \
		libgnutls-dev doxygen \
		libcurl4-nss-dev libexpat1-dev libxml2-dev \
	&& \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

# trusty provides protobuf 0.15, which is older than our required 1.0.0-rc2
