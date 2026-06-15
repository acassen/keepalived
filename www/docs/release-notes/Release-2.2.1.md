# Release 2.2.1 `17th January 2021`

This release fix some minor regressions brought by last release.

## Improvements

- **core**: Remove unused fallback definitions of W_EXITCODE and WCODEFLAG.

- **check**: Correct cast type of address parameter in sendto() call.

- **parser**: set O_CLOEXEC on re-opened config file copy.

## Fixes

- **parser**: Fix building with Musl libc.

- **build**: Fix use of date command in Makefile when using Busybox.

- **tracker**: fix building with gcc requiering inttypes.h.

- **parser**: Fix handling of configurations larger than 4096 bytes.
