FROM centos/systemd:latest
ARG ARG_PH_USER
ARG ARG_PH_PASS
RUN yum update -y && yum clean all
RUN yum install -y vim \
	expect \
	crontabs \
	&& yum clean all
RUN yum-config-manager --add-repo=https://repo.phantom.us/phantom/4.10/base/7/x86_64/
RUN yum update -y && yum install -y phantom_repo --nogpgcheck && yum clean all \
	&& rm /etc/yum.repos.d/repo.phantom.us_phantom_4.10_base_7_x86_64_.repo
RUN echo "#!/usr/bin/expect" >> /tmp/install_wrapper && \
	echo "set timeout 10" >> /tmp/install_wrapper && \
	echo "spawn /opt/phantom/bin/phantom_setup.sh install --no-prompt --no-space-check" >> /tmp/install_wrapper && \
	echo "expect \"Enter username:\"" >> /tmp/install_wrapper && \
	echo "send \"${ARG_PH_USER}\r\"" >> /tmp/install_wrapper && \
	echo "expect \"Enter password:\"" >> /tmp/install_wrapper && \
	echo "send \"${ARG_PH_PASS}\r\"" >> /tmp/install_wrapper && \
	chmod +x /tmp/install_wrapper
#	echo "interact" >> /tmp/install_wrapper && chmod +x /tmp/install_wrapper
RUN /tmp/install_wrapper
# Parse out container ID from shell
