# News

The most recent project announcements and release updates. For the full
history of changes, read the [Release Notes](release-notes/index.md) and the
[ChangeLog](documentation/changelog.md).

## 2026

- **June 22 · Release 2.4.0**. A major release adding the `auth_hmac` VRRP authentication extension, a broad security hardening pass, and a rebuilt website. [Release Notes](release-notes/Release-2.4.0.md)
- **June 20 · VRRP HMAC authentication**. A new `auth_hmac` extension adds origin authentication, integrity and replay protection to VRRP adverts. It closes the off-segment injection hole that unicast deployments inherit once the TTL=255 guard no longer applies, and an upcoming IETF Internet-Draft specifies the wire format. [Read the article](articles/vrrp-hmac-authentication.md)

## 2025

- **June 10 · Release 2.3.4**. Fixes minor issues and improves the build process. [Release Notes](release-notes/Release-2.3.4.md)
- **March 30 · Release 2.3.3**. Brings improvements, fixes reported issues and adds security provisions for the VRRP code. Thanks to the constructive work done with Orange Cyberdefense in Lyon, France. [Release Notes](release-notes/Release-2.3.3.md)

## 2024

- **November 3 · Release 2.3.2**. Improvements and fixes for reported issues. [Release Notes](release-notes/Release-2.3.2.md)
- **May 24 · Release 2.3.1**. A short release that fixes a minor regression. [Release Notes](release-notes/Release-2.3.1.md)
- **May 21 · Release 2.3.0**. Improvements and minor fixes. [Release Notes](release-notes/Release-2.3.0.md)

## 2023

- **May 31 · Release 2.2.8**. Improvements, fixes and new VRRP and BFD features. [Release Notes](release-notes/Release-2.2.8.md)

## 2022

- **January 16 · Release 2.2.7**. Many improvements and fixes, new VRRP features and even stronger stability. [Release Notes](release-notes/Release-2.2.7.md)

## 2021

- **August 21 · Release 2.2.4**. Fixes minor build issues and closes all open Coverity findings. [Release Notes](release-notes/Release-2.2.4.md)
- **August 14 · Release 2.2.3**. New features and minor fixes. The `genhash` utility joins the mainline daemon. [Release Notes](release-notes/Release-2.2.3.md)
- **March 5 · Release 2.2.2**. Fixes minor systemd integration issues and drops old kernel support. [Release Notes](release-notes/Release-2.2.2.md)
- **January 17 · Release 2.2.1**. Fixes minor regressions from the previous release. [Release Notes](release-notes/Release-2.2.1.md)
- **January 9 · Release 2.2.0**. A major milestone with a bunch of new features and extensions, focused on corner cases and resilient handling. [Release Notes](release-notes/Release-2.2.0.md)

## 2020

- **June 13 · Release 2.1.0**. A large effort revisiting the whole code to reach carrier grade quality. This release also moved the project to a Release Notes process. [Release Notes](release-notes/Release-2.1.0.md)
- **January 22 · Release 2.0.20**. A very stable release after strong debugging iterations during the year.

## 2019

- **July 26**. Keepalived is now referenced by the [Technical Reference Model of the U.S. Department of Veterans Affairs](https://www.oit.va.gov/Services/TRM/ToolPage.aspx?tid=11251).
- **May 26**. Created the [Keepalived account on X](https://twitter.com/keepalived) for release announcements and updates.
- **May 24**. Created the [Keepalived Users Group](https://groups.io/g/keepalived-users) at Groups.io, which replaces the old SourceForge mailing lists.
- **May 16**. A new logo for Keepalived.

## Earlier milestones

- **2018-05-26 · Release 2.0.0**. A major release after about two years of hard work, with many components reworked for high performance.
- **2012-07-12**. Created the [Keepalived GitHub repository](https://github.com/acassen/keepalived), which became the official master git repository.
- **2011-11-23**. Alexandre Simon presented Keepalived at JRES 2011, with a [paper](pdf/asimon-jres-paper.pdf) and [slides](pdf/asimon-jres-slides.pdf).
- **2000-12-22 · Release 0.2.1**. The first public release.
