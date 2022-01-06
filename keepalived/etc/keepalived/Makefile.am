# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>

cp = echo "  CP       $@"; \
      cp

@DEFAULT_CONFIG_FILENAME@.sample: $(srcdir)/keepalived.conf.sample.in
	@$(cp)  '$<' $@

EXTRA_DIST		= keepalived.conf.sample.in

configdir		= @DEFAULT_CONFIG_DIR@
config_DATA		= @DEFAULT_CONFIG_FILENAME@.sample

MOSTLYCLEANFILES	= @DEFAULT_CONFIG_FILENAME@.sample

# If $DESTDIR is not blank, the following changes are not done since it is assumed to be a staged
# installation. This means it will not apply to distros building keepalived.
# After keepalived v2.2.4 we stopped installing a default keepalived.conf and instead install
# keepalived.conf.sample. We also fixed a bug in keepalived where it always used /etc/keepalived.conf
# rather than $(configdir)/keepalived.conf as the default configuration file.
# The following checks if $(configdir)/keepalived.conf exists and if it matches one of the sample
# config files (any version since keepalived v0.6.6) (the series of sed commands edit older versions
# to match the current version), and if it matches, simply removes the config file (since it can't
# be used to run keepalived), then if $configdir is not /etc copies /etc/keepalived.conf to $configdir
# and updates /etc/keepalived.conf with a comment at the beginning to state that the configuration
# file has been moved to $configdir.
# The code below incorporates $(DESTDIR) to facilitate testing if the test -z $(DESTDIR) is changed to
# test -n $(DESTDIR).
install-data-hook:
	@if test -z "$(DESTDIR)" && test -f $(DESTDIR)$(configdir)/@DEFAULT_CONFIG_FILENAME@; then \
		tr "\n" "~" <$(DESTDIR)$(configdir)/@DEFAULT_CONFIG_FILENAME@ | \
			@SED@ -e "s/\(10.10.10.2 1358 {~    delay_loop 6~    lb_algo rr ~    lb_kind NAT~\)    nat_mask 255.255.255.0~/\1/" | \
			@SED@ -e "s/lvs_id /router_id /" | \
			@SED@ -e "s/~[^~]*nat_mask[^~]*~/~/g" | \
			@SED@ -e "s/\(~   router_id LVS_DEVEL~\)}/\1   vrrp_skip_check_adv_addr~}/" | \
			@SED@ -e "s/\(~   vrrp_skip_check_adv_addr~\)}/\1   vrrp_strict~}/" | \
			@SED@ -e "s/\(~   vrrp_strict~\)}/\1   vrrp_garp_interval 0~   vrrp_gna_interval 0~}/" | \
			@SED@ -e "s/ ~/~/g" | \
			@SED@ -e "s/nb_get_retry/retry/g" | \
			tr "~" "\n" | \
			diff -q - $(DESTDIR)$(configdir)/@DEFAULT_CONFIG_FILENAME@.sample; \
		if test $$? -eq 0; then \
			rm $(DESTDIR)$(configdir)/@DEFAULT_CONFIG_FILENAME@; \
		fi; \
	fi;
