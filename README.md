
![Tests](https://github.com/nNipsx-Sec/pySigma-backend-qradar/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Qradar Backend

This is the Qradar backend for pySigma. It provides the package `sigma.backends.qradar` with the `QradarBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.qradar`:

* qradar_windows: Qradar Windows log support. Applied automatically in `default` output format.
* qradar_exetension: Generate Extension rules for Qradar; Easier for deploy rules as a part of Detection as Code will
  release in near furture. Applied automatically in `extension` output format.

It supports the following output formats:

* default: Qradar AQL queries
* extension: Create Extensions rules for Qradar. (Support only Qradar v7.4.0)

This backend is currently maintained by:

* [nNipsx](https://github.com/nNipsx-Sec) aka Duc.Le from GTSC Team

Supported by:
* Dinh.Bui, Tuan.Le, Hieu.Le, Khanh.Bui - GTSC Team

Special thanks to [thomaspatzke](https://github.com/thomaspatzke) 

Pre-release Qradar Backend with new module for generate extensions Only Support Qradar v7.4.0 above for easier deploy rules in this SIEM

With pipeline of Qradar, now i can't list and mapping all field so i'll try update full field in near future

With new feature for Qradar is Extensions:

1. I have build base on offense with create 1 Building block (corresponding with 1 sigma rules) and 1 rules contain this building block for easier manage and add whitelist when tuning rules.
2. I have build some mapping with QID and Log Source instead of using full AQL => Increase performance Qradar when working
This backend i build base on Splunk Backend and maybe it's have some issue please tell me so i'll fix soon ASP
3. After create extension will be generate file with extension .zip. You can using this files and upload and install extensions in Qradar.
4. **Recommend testing extensions in UAT or Dev/test enviroments**

