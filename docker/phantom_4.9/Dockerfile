FROM centos/systemd

RUN yum update -y

ARG myphantomuser
ARG myphantompass
ENV USER=$myphantomuser
ENV PASS=$myphantompass
COPY run_setup.sh /tmp/run_setup.sh

RUN rpm -Uvh https://repo.phantom.us/phantom/4.9/base/7/x86_64/phantom_repo-4.9.34514-1.x86_64.rpm
# RUN /opt/phantom/bin/phantom_setup.sh install --no-prompt