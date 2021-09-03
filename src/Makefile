RELEASE := 3.0.0-rc1
BUILDID := $(if $(SVN_REVISION),$(SVN_REVISION),$(shell git rev-list --count HEAD))
BUILD_DIR := pkg_build
SRC_DIR := recordedfuture
PACKAGE := recordedfuture-$(RELEASE).tgz
RFUSERARG := $(if ${RFLDAP},-l ${RFLDAP},)
SCPHOST := $(if ${RFLDAP},${RFLDAP}@${PH},${PH})
RESULT_FILES := reputation_results.html \
	intelligence_results.html \
	threat_assessment_results.html \
	contexts_results.html \
	alert_rules_results.html \
	alert_data_results.html
STYLESHEET := recordedfuture_style.css
RF_SRC := $(addprefix $(SRC_DIR)/,$(RESULT_FILES))
RF_DEST := $(addprefix $(BUILD_DIR)/,$(RESULT_FILES))
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
	@echo "  setup_docker  - will copy id_rsa.pub to the phantom user authorized key on "
	@echo "                  the phantom docker container."
	@echo
	@echo "If your LDAP username name differs from you local one, set RFLDAP to your LDAP username"


##########################################
#
# Targets related to build
#
##########################################
build: build_rsync build_style build_json build_readme build_consts

build_rsync: build_dirs
	$(LOCAL_RSYNC) -ra recordedfuture/ $(BUILD_DIR)/ \
		--exclude=recordedfuture.json \
		--exclude=recordedfuture_consts.py \
		--exclude=readme.html \
        --exclude=*.pyc \
        --exclude=*results.html \
        --exclude=recordedfuture_style.css

build_style: $(RF_DEST)

$(BUILD_DIR)/%.html: $(SRC_DIR)/%.html
	$(SED) -e "/$(STYLESHEET)/r $(SRC_DIR)/$(STYLESHEET)" < $^ > $@

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
	scp ~/.ssh/id_rsa.pub $(SCPHOST):/tmp/
	$(SSHRAW) $(PH) "sudo -u phantom mkdir -p ~phantom/.ssh; \
	                 sudo -u phantom chmod go= ~phantom/.ssh; \
	                 sudo mv /tmp/id_rsa.pub ~phantom/.ssh/authorized_keys; \
	                 sudo chown phantom ~phantom/.ssh/authorized_keys"
setup_docker:
	docker exec -it rf_phantom mkdir -p /home/phantom/.ssh
	docker exec -it rf_phantom chmod go= /home/phantom/.ssh
	docker cp ~/.ssh/id_rsa.pub rf_phantom:/home/phantom/.ssh/authorized_keys
	docker exec -it rf_phantom chown phantom /home/phantom/.ssh/authorized_keys
