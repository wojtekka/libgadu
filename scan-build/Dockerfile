FROM libgadu/builder-ubuntu:xenial

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		clang \
	&& \
	apt-get remove -y \
		doxygen \
	&& \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*
