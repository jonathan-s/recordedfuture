FROM centos/systemd:latest
RUN yum update -y && yum clean all
RUN yum-config-manager --add-repo=https://repo.phantom.us/phantom/4.10/base/7/x86_64/
RUN yum update -y && yum install -y phantom_repo --nogpgcheck && yum clean all \
	&& rm /etc/yum.repos.d/repo.phantom.us_phantom_4.10_base_7_x86_64_.repo
# Now you need to do manual installation on the product
# Add license
# Execute curl to open up request from anywhere
