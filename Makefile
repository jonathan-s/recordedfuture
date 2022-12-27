RELEASE := 4.1.0
BUILDID := $(if $(SVN_REVISION),$(SVN_REVISION),$(shell git rev-list --count HEAD))
BUILD_DIR := pkg_build
SRC_DIR := src/recordedfuture
PACKAGE := recordedfuture-$(RELEASE).tgz
RFUSERARG := $(if ${RFLDAP},-l ${RFLDAP},)
SCPHOST := $(if ${RFLDAP},${RFLDAP}@${PH},${PH})
RESULT_FILES := reputation_results.html \
	intelligence_results.html \
	threat_assessment_results.html \
	contexts_results.html \
	alert_rule_search_results.html \
	alert_search_results.html \
	alert_lookup_results.html \
	alert_update_results.html \
	list_search_results.html \
	list_create_results.html \
	list_details_results.html \
	list_status_results.html \
	list_entities_results.html \
	list_entities_management_results.html
STYLESHEET := recordedfuture_style.css
RF_SRC := $(addprefix $(SRC_DIR)/,$(RESULT_FILES))
RF_DEST := $(addprefix $(BUILD_DIR)/,$(RESULT_FILES))
PH_PORT:= 22
LOCAL_RSYNC := rsync
SSH_KEY_FILE_ARGS := $(if ${SSH_KEY_FILE},-i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no,)
SSH := ssh -p $(PH_PORT) $(SSH_KEY_FILE_ARGS) -l phantom
RSYNC := env RSYNC_RSH="ssh $(SSH_KEY_FILE_ARGS) -p $(PH_PORT)" rsync -rav
SSHRAW := ssh -p $(PH_PORT) -t $(RFUSERARG)
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
# Targets needs to be implemented for build pipeline
#
##########################################

review:
	echo "make review not implemented"

unittests:
	echo "make unittests not implemented"

itests_mock:
	echo "make itests_mock not implemented"

itests_live:
	echo "make itests_live not implemented"

uitests_mock:
	echo "make uitests_mock not implemented"

uitests_live:
	echo "make uitests_live not implemented"

##########################################
#
# Targets related to build
#
##########################################
build: build_rsync build_style build_json build_readme build_consts

build_rsync: build_dirs
	$(LOCAL_RSYNC) -ra $(SRC_DIR)/ $(BUILD_DIR)/ \
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

$(BUILD_DIR)/recordedfuture.json: $(SRC_DIR)/recordedfuture.json
	$(SED) -e "s/%RELEASE%/$(RELEASE)/" \
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
	              (phenv compile_app -i);";
	$(RSYNC) phantom@$(PH):/tmp/$(MYTMPDIR)/recordedfuture/recordedfuture.tgz $@
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
	scp $(SSH_KEY_FILE_ARGS) -P $(PH_PORT) ~/.ssh/id_rsa.pub $(SCPHOST):/tmp/
	$(SSHRAW) $(PH) "sudo -u phantom mkdir -p ~phantom/.ssh; \
	                 sudo -u phantom chmod go= ~phantom/.ssh; \
	                 sudo mv /tmp/id_rsa.pub ~phantom/.ssh/authorized_keys; \
	                 sudo chown phantom ~phantom/.ssh/authorized_keys"
setup_docker:
	docker exec -it rf_phantom mkdir -p /home/phantom/.ssh
	docker exec -it rf_phantom chmod go= /home/phantom/.ssh
	docker cp ~/.ssh/id_rsa.pub rf_phantom:/home/phantom/.ssh/authorized_keys
	docker exec -it rf_phantom chown -R phantom:phantom /home/phantom/.ssh
