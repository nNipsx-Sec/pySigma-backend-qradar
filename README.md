
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Qradar Backend

This is the Qradar backend for pySigma. It provides the package `sigma.backends.qradar` with the `QradarBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.qradar`:

* qradar_windows_events_acceleration_keywords: Qradar Windows log support
* qradar_cim_exetension: Generate Extension rules for Qradar; Easier for deploy rules as a part of Detection as Code will release in near furture

It supports the following output formats:

* savedsearches: Qradar AQL queries
* extensions: Create Extensions rules for Qradar.

This backend is currently maintained by:

* [nNipsx](https://github.com/nNipsx-Sec) aka Duc.Le from GTSC Team