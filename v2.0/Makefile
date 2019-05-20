RELEASE := 2.0.0
BUILDID := $(shell svn info --show-item revision)
BUILD_DIR := pkg_build
SRC_DIR := recordedfuture
PACKAGE := recordedfuture-$(RELEASE).tgz
RFUSERARG := $(if ${RFLDAP},"-l ${RFLDAP}","")

RSYNC := env RSYNC_RSH=ssh rsync -rav
LOCAL_RSYNC := rsync
SSH := ssh -l phantom
SSHRAW := ssh -t $(RFUSERARG)
SED := sed
MKDIR_P = mkdir -p
MYTMPDIR := $(shell basename `mktemp -d -u`)

all:
	@echo Targets for make:
	@echo "  build         - will build a ready-for-import set of files in $(BUILD_DIR)."
	@echo "  package       - will build the package on a Phantom server and retreive it."
	@echo "  setup_ssh     - will copy id_rsa.pub to the phantom user authorized key on "
	@echo "                  the phantom server."
	@echo
	@echo "If your LDAP username name differs from you local one, set RFLDAP to your LDAP username"


##########################################
#
# Targets related to build
#
##########################################
build: build_rsync build_json build_readme build_consts

build_rsync: build_dirs
	$(LOCAL_RSYNC) -ra recordedfuture/ $(BUILD_DIR)/ \
		--exclude=recordedfuture.json \
		--exclude=recordedfuture_consts.py \
		--exclude=readme.html \
		--exclude=*.pyc

build_json: $(BUILD_DIR)/recordedfuture.json build_dirs

$(BUILD_DIR)/recordedfuture.json: $(SRC_DIR)/recordedfuture.json
	$(SED) -e "s/%RELEASE%/$(RELEASE)/" \
           -e "s/%BUILDID%/$(BUILDID)/" \
           < $^ > $@

build_consts: $(BUILD_DIR)/recordedfuture_consts.py build_dirs

$(BUILD_DIR)/recordedfuture_consts.py: $(SRC_DIR)/recordedfuture_consts.py
	$(SED) -e "s/%RELEASE%/$(RELEASE)/" \
           -e "s/%BUILDID%/$(BUILDID)/" \
           < $^ > $@

build_readme: $(BUILD_DIR)/readme.html build_dirs

$(BUILD_DIR)/readme.html: $(SRC_DIR)/readme.html
	$(SED) -e "s/%RELEASE%/$(RELEASE)/" \
           -e "s/%BUILDID%/$(BUILDID)/" \
           < $^ > $@

build_dirs: $(BUILD_DIR)

$(BUILD_DIR):
	$(MKDIR_P) $(BUILD_DIR)


##########################################
#
# Targets related to package
#
##########################################
package: $(PACKAGE)

$(PACKAGE): build
	if [ "x$(PH)" = "x" ]; then \
		echo Environment variable PH must contain the hostname of the phantom server.;\
		exit 1; \
	fi
	$(SSH) $(PH) "mkdir -p /tmp/$(MYTMPDIR)/recordedfuture"
	$(RSYNC) $(BUILD_DIR)/* phantom@$(PH):/tmp/$(MYTMPDIR)/recordedfuture
	$(SSH) $(PH) "cd /tmp/$(MYTMPDIR)/recordedfuture; chmod -R a+w ..; \
	              (phenv python2.7 /opt/phantom/bin/compile_app.pyc -i);";
	$(RSYNC) phantom@$(PH):/tmp/$(MYTMPDIR)/recordedfuture.tgz $@
	$(SSH) $(PH) "rm -rf /tmp/$(MYTMPDIR)"

##########################################
#
# Misc targets
#
##########################################
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(PACKAGE)

setup_ssh:
	@if [ "x$(PH)" = "x" ]; then \
		echo Environment variable PH must contain the hostname of the phantom server.;\
		exit 1; \
	fi
	scp ~/.ssh/id_rsa.pub $(PH):/tmp/
	$(SSHRAW) $(PH) "sudo -u phantom mkdir -p ~phantom/.ssh; \
	                 sudo -u phantom chmod go= ~phantom/.ssh; \
	                 sudo -u phantom cp /tmp/id_rsa.pub ~phantom/.ssh/authorized_keys; \
	                 sudo chown phantom ~phantom/.ssh/authorized_keys"