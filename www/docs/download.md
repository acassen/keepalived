# Download

## Latest stable release

!!! success "Keepalived 2.4.0"

    Released June 22, 2026.
    [:material-download: keepalived-2.4.0.tar.gz](software/keepalived-2.4.0.tar.gz){ .md-button .md-button--primary }
    [:material-text-box-outline: Release Notes](release-notes/Release-2.4.0.md){ .md-button }

    `MD5  efff185055cdc68864cf408336974f76`

## Install from your distribution

The main website does not provide binary packages. Most Linux distributions
ship Keepalived as a mainline package, and the package maintainers do a great
job keeping it current and reporting issues. Installing from your distribution
is the quickest path:

=== "Debian / Ubuntu"

    ```sh
    sudo apt install keepalived
    ```

=== "RHEL / Fedora / Rocky"

    ```sh
    sudo dnf install keepalived
    ```

=== "Arch Linux"

    ```sh
    sudo pacman -S keepalived
    ```

=== "Alpine"

    ```sh
    sudo apk add keepalived
    ```

## Build from source

Clone the official repository and build the current tree, which is considered
stable and future proof:

```sh
git clone https://github.com/acassen/keepalived.git
cd keepalived
./configure
make && sudo make install
```

You can also download the source tarball of any release below and verify it
against the published MD5 checksum before building.

## Stable releases

| Version | Date | MD5 | Notes |
| --- | --- | --- | --- |
| [2.4.0](software/keepalived-2.4.0.tar.gz) | 2026-06-22 | `efff185055cdc68864cf408336974f76` | [Release Notes](release-notes/Release-2.4.0.md) |
| [2.3.4](software/keepalived-2.3.4.tar.gz) | 2025-06-10 | `622b09f4502ada4c6d20ef1c29205f77` | [Release Notes](release-notes/Release-2.3.4.md) |
| [2.3.3](software/keepalived-2.3.3.tar.gz) | 2025-03-30 | `c7b5023bff83655247590b254ff630c8` | [Release Notes](release-notes/Release-2.3.3.md) |
| [2.3.2](software/keepalived-2.3.2.tar.gz) | 2024-11-03 | `a5e84e7a7b6d37dc5378c14fcfad1574` | [Release Notes](release-notes/Release-2.3.2.md) |
| [2.3.1](software/keepalived-2.3.1.tar.gz) | 2024-05-24 | `5434ebc3becb6f86ebc3adc04e3e7e6d` | [Release Notes](release-notes/Release-2.3.1.md) |
| [2.3.0](software/keepalived-2.3.0.tar.gz) | 2024-05-21 | `ffd7f6f158361e8a511016136dd2eaea` | [Release Notes](release-notes/Release-2.3.0.md) |
| [2.2.8](software/keepalived-2.2.8.tar.gz) | 2023-05-31 | `8c26f75a8767e5341d82696e1e717115` | [Release Notes](release-notes/Release-2.2.8.md) |
| [2.2.7](software/keepalived-2.2.7.tar.gz) | 2022-01-16 | `5f310b66a043a1fb31acf65af15e95bc` | [Release Notes](release-notes/Release-2.2.7.md) |
| [2.2.4](software/keepalived-2.2.4.tar.gz) | 2021-08-21 | `7097ba70a7c6c46c9e478d16af390a19` | [Release Notes](release-notes/Release-2.2.4.md) |
| [2.2.3](software/keepalived-2.2.3.tar.gz) | 2021-08-14 | `9a9dc19e130c6b67d6de3ff2fdae063e` | [Release Notes](release-notes/Release-2.2.3.md) |
| [2.2.2](software/keepalived-2.2.2.tar.gz) | 2021-03-05 | `2e86bade4a7a48cfac7d35a6c9643d46` | [Release Notes](release-notes/Release-2.2.2.md) |
| [2.2.1](software/keepalived-2.2.1.tar.gz) | 2021-01-17 | `8379ea814279cfd20ee8d08f6e384acf` | [Release Notes](release-notes/Release-2.2.1.md) |
| [2.2.0](software/keepalived-2.2.0.tar.gz) | 2021-01-09 | `323b32c20d3bd891aabaab27d9f42ea0` | [Release Notes](release-notes/Release-2.2.0.md) |
| [2.1.5](software/keepalived-2.1.5.tar.gz) | 2020-07-13 | `27e1cfff5b8dd95062ad415957e663e5` | [Release Notes](release-notes/Release-2.1.5.md) |
| [2.1.4](software/keepalived-2.1.4.tar.gz) | 2020-07-10 | `a4c021db8110517382a825cacbf837f6` | [Release Notes](release-notes/Release-2.1.4.md) |
| [2.1.3](software/keepalived-2.1.3.tar.gz) | 2020-06-23 | `3255a15b0c317749beb3625167b33efc` | [Release Notes](release-notes/Release-2.1.3.md) |
| [2.1.2](software/keepalived-2.1.2.tar.gz) | 2020-06-14 | `8548a3859471ef1a28136d801c52dd3e` | [Release Notes](release-notes/Release-2.1.2.md) |
| [2.1.0](software/keepalived-2.1.0.tar.gz) | 2020-06-13 | `8d59b1188f11ee90ad5f966b268bf41b` | [Release Notes](release-notes/Release-2.1.0.md) |

## Older releases

Every historical tarball back to version 0.2.1 (December 2000) remains
available. Browse the full set on the [GitHub releases
page](https://github.com/acassen/keepalived/releases) and the [git
tags](https://github.com/acassen/keepalived/tags), or read the complete
[ChangeLog](documentation/changelog.md) for details on each version.
