# Release 2.2.4 `21th August 2021`

This release fix some minor build issues brought by last release. All coverity spotted issues has been fixed.

## Fixes

- **build**: stop looping when sbindir = bindir

- **build**: don't inherit LTO flags from net-snmp-config --cflags-only-other

- **build**: use realpath where available to work out relative path for genhash

- **build**: fix some compile errors on RHEL 7

- **build**: fix building with OpenSSL prior to v1.1.0

- **coverity**: fix all spotted issues
