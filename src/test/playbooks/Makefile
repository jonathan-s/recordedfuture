 PACKAGES := recorded_future_reputation_test.tgz  \
 		recorded_future_intelligence_test.tgz  \
		recorded_future_reputation_parameter_test.tgz  \
                recorded_future_intelligence_parameter_test.tgz  \
		recorded_future_alert_test.tgz
DIST_DIR := pkg_build
PKG_TARGETS := $(addprefix $(DIST_DIR)/,$(PACKAGES))
# COPYFILE prevents tar on Macos to add virtual files for file permissions to archive.
# Phantom can't deal with those files.
COPYFILE := $(shell if [ "x`tar --version | cut -d' ' -f1`" = "xbsdtar" -a "x`uname`" = "xDarwin" ]; then echo --disable-copyfile; fi)
PRIVATE_KEYWORDS := 'recfut|@recordedfuture'

all:
	@echo "Handle Phantom TEST playbook packages"
	@echo "Targets:"
	@echo "  packages      - make packages"
	@echo "  clean         - remove all .pyc files and built packages"

packages: $(PKG_TARGETS)

dist_dirs: $(DIST_DIR)

$(DIST_DIR):
	mkdir $(DIST_DIR)

$(DIST_DIR)/%.tgz: dist_dirs
	@if [ "x`egrep -rl $(PRIVATE_KEYWORDS) $(@F:.tgz=)`" != "x" ]; then \
		echo The playbook $(@F:.tgz=) contains internal emails or hosts.; \
		echo `egrep -r $(PRIVATE_KEYWORDS) $(@F:.tgz=)`; \
		exit 1; \
	fi
	(cd $(@F:.tgz=); \
	 tar zcvf ../$@ $(COPYFILE) \
		$(@F:.tgz=).json \
		$(@F:.tgz=).py)

clean:
	rm -f */*.pyc
	rm -rf $(DIST_DIR)
