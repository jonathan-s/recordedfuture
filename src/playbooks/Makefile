PACKAGES := recorded_future_correlation.tgz \
			recorded_future_enrichment.tgz \
			recorded_future_handle_leaked_credentials.tgz \
 			recorded_future_correlation_slack.tgz \
                        recorded_future_enrichment_slack.tgz \
                        recorded_future_handle_leaked_credentials_slack.tgz \
			recorded_future_threat_assessment_slack.tgz
DIST_DIR := pkg_build
PKG_TARGETS := $(addprefix $(DIST_DIR)/,$(PACKAGES))
# COPYFILE prevents tar on Macos to add virtual files for file permissions to archive.
# Phantom can't deal with those files.
COPYFILE := $(shell if [ "x`tar --version | cut -d' ' -f1`" = "xbsdtar" -a "x`uname`" = "xDarwin" ]; then echo --disable-copyfile; fi)
# VNPVFc is a leaked credentials rule id used during dev (all fake data so not sensitive but still)
PRIVATE_KEYWORDS := 'recfut|@recordedfuture|splunk-ps|VNPVFc'

all:
	@echo "Handle Phantom playbook packages"
	@echo "Targets:"
	@echo "  packages      - make packages"

packages: $(PKG_TARGETS)

dist_dirs: $(DIST_DIR)

$(DIST_DIR):
	mkdir $(DIST_DIR)

info_security:

$(DIST_DIR)/%.tgz: dist_dirs
	if [ "x`egrep -rl $(PRIVATE_KEYWORDS) $(@F:.tgz=)`" != "x" ]; then \
		echo The playbook $(@F:.tgz=) contains internal emails or hosts.; \
		echo `egrep -r $(PRIVATE_KEYWORDS) $(@F:.tgz=)`; \
		exit 1; \
	fi
	(cd $(@F:.tgz=); \
	 tar zcvf ../$@ $(COPYFILE) \
		$(@F:.tgz=).json \
		$(@F:.tgz=).py)

