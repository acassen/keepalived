# Release 2.3.1 `24th May 2024`

This is minutes release to quickly fix minor regression.

## Fixes

- **conf**: fix secondary config file location when using --prefix=/usr Commit 42a746c - "configure: ${prefix} defaults to NONE which messes up DEFAULT_CONFIG_FILE" broke the checking of whether a secondary default config file location is required.
