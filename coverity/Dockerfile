FROM libgadu/builder-opensuse:42.1

RUN zypper -n install \
		curl \
	&& \
	zypper -n clean --all

ENV PATH=/cov-analysis-linux64-7.7.0.4/bin:$PATH

ADD .deps/cov-analysis.tar.gz /
