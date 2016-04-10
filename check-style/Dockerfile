FROM opensuse:42.1

RUN zypper addrepo -f -G \
		http://download.opensuse.org/repositories/home:/tomkiewicz:/linux/openSUSE_Leap_42.1/ home:tomkiewicz:linux \
	&& \
	zypper -n install \
		git vera++ \
	&& \
	zypper -n clean --all
