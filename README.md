osmo-msc - Osmocom MSC Implementation
=====================================

This repository contains a C-language implementation of a GSM Mobile Switching
Centre (MSC) for 2G (GSM) and 3G (UMTS).  It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

OsmoMSC exposes
 * A over IP towards BSCs (e.g. OsmoBSC): 3GPP AoIP or SCCPlite
 * IuCS over IP towards RNCs / HNBGW (e.g. osmo-hnbgw)
 * The Osmocom typical telnet VTY and CTRL interfaces.
 * The Osmocom typical statsd exporter.

OsmoMSC implements
 * mobility management
 * call control (either via built-in MNCC handler or external osmo-sip-connector)
 * USSD (exposed via GSUP)
 * SMS (either via built-in SMSC or external via GSUP)

Homepage
--------

You can find the OsmoMSC issue tracker and wiki online at
<https://osmocom.org/projects/osmomsc> and <https://osmocom.org/projects/osmomsc/wiki>.


GIT Repository
--------------

You can clone from the official osmo-msc.git repository using

        git clone https://gitea.osmocom.org/cellular-infrastructure/osmo-msc

There is a web interface at <https://gitea.osmocom.org/cellular-infrastructure/osmo-msc>


Documentation
-------------

User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmomsc-usermanual.pdf)
as well as the [VTY Reference Manual](https://ftp.osmocom.org/docs/latest/osmomsc-vty-reference.pdf)


Mailing List
------------

Discussions related to osmo-msc are happening on the
openbsc@lists.osmocom.org mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/openbsc> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We us a gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for osmo-msc can be seen at
<https://gerrit.osmocom.org/#/q/project:osmo-msc+status:open>


History
-------

OsmoMSC originated from the OsmoNITB project, which started as a minimalistic
all-in-one implementation of the GSM Network. In 2017, OsmoNITB had reached
maturity and diversity (including M3UA SIGTRAN and 3G support in the form of
IuCS and IuPS interfaces) that naturally lead to a separation of the all-in-one
approach to fully independent separate programs as in typical GSM networks.

OsmoMSC was one of the parts split off from the old openbsc.git.
