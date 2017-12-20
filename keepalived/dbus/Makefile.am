# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

# XML_MATCH is used for converting an .xml_template file into an
# .xml file. Any lines in the .xml_template file that don't start with
# a string of capital letters followed by a tab or new line will be passed
# through to the .xml file. If XML_FILE comprises a capital letter, then lines
# that have that capital letter in an initial string of capitals will also be
# passed to the .xml file, but with the initial capitals and tab removed.
# e.g. if XML_MATCH = C, then
# ABCD	fred		# will be passed through as 'fred' and
# ABXY	joe		# will not be passed
#
# Below are further more complex examples:
# XML_MATCH = C[A-Z]*X	# pass lines that have a C followed by an X (possibly with other letters in between)
# XML_MATCH = [CX]	# pass lines their have C or X (or both)
# XML_MATCH = [CX][A-Z]*[CX] # pass lines with C and X in either order (or two C's or two X's)
#			     # C[A-Z]*X is preferred if all option letters are in alphabetical order

if DBUS_CREATE_INSTANCE
XML_MATCH	= C
else
XML_MATCH	= None
endif

org.@PACKAGE@.Vrrp1.Vrrp.xml:	Makefile

.xml_template.xml:
	@echo "  SED      $@"
	@@SED@ -e "s/^[A-Z]*$(XML_MATCH)[A-Z]*	//" -e "s/^[A-Z]*$(XML_MATCH)[A-Z]*$$//" -e "/^[A-Z]/d" $< >$@

EXTRA_DIST		= org.@PACKAGE@.Vrrp1.Vrrp.xml_template

dbusinterfacedir	= @datadir@/dbus-1/interfaces
dist_dbusinterface_DATA	= org.@PACKAGE@.Vrrp1.Instance.xml
inst_dbusinterfacedir	= @datadir@/dbus-1/interfaces
inst_dbusinterface_DATA	= org.@PACKAGE@.Vrrp1.Vrrp.xml

dbussystemdir		= @sysconfdir@/dbus-1/system.d
dist_dbussystem_DATA	= org.@PACKAGE@.Vrrp1.conf

mostlyclean-local:
	-rm -rf org.@PACKAGE@.Vrrp1.Vrrp.xml
