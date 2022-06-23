![Tests](https://github.com/nNipsx-Sec/pySigma-backend-qradar/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## Overview
This is the Qradar backend for [pySigma](https://github.com/SigmaHQ/pySigma), capable of converting Sigma rules into two type: *Ariel Query Language* and *Extension Package* compatible with the Qradar SIEM. It provides the package `sigma.backends.qradar` with the `QradarBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.qradar`:
* qradar_windows: Qradar Windows log support. Applied automatically in `default` output format.
* qradar_exetension: Generate Extension package rules for Qradar; Easier for deploy rules as a part of Detection as Code will
  release in near furture. Applied automatically in `extension` output format.

## Installation
Qradar Backend is now part of Sigma CLI. Run command below 
```
python -m pip install sigma-cli
```
Ref: https://github.com/SigmaHQ/sigma-cli
## pySigma Qradar Backend

This is the Qradar backend for pySigma. It provides the package `sigma.backends.qradar` with the `QradarBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.qradar`:

* qradar_windows: Qradar Windows log support. Applied automatically in `default` output format.
* qradar_exetension: Generate Extension rules for Qradar; Easier for deploy rules as a part of Detection as Code will
  release in near furture. Applied automatically in `extension` output format.

## Output Format Support
It supports the following output formats:

* default: Qradar AQL queries
* extension: Create Extensions rules for Qradar. (Support only Qradar v7.4.0)

## Contributor
This backend is currently maintained by:

* [nNipsx](https://github.com/nNipsx-Sec) aka Duc.Le from GTSC Team

Supported by:
* Dinh.Bui, Tuan.Le, Hieu.Le, Khanh.Bui - GTSC Team

Special thanks to [thomaspatzke](https://github.com/thomaspatzke) 

## How it work
### Qradar Extension Package
With new feature for Qradar is Extensions Qradar have two type rules is [Building Blocks](https://www.ibm.com/docs/en/qsip/7.4?topic=phase-qradar-building-blocks) and [Rules](https://www.ibm.com/docs/en/qsip/7.4?topic=phase-qradar-rules-offenses). Base on that Qradar Backend Extension convert put all rule conditions to `Building Blocks` then create `Rules` contain this building block for easier manage and add whitelist when tuning rules.
Example: 

![image BB](/docs/images/BBlock.png)

![Image Rules](/docs/images/Rules.png)

*With Qradar Extension, Product (Ex: Windows, Linux, ..) and EventID will convert to LogSourceID and QID provide by Qradar; it's increase performance when processing logs and trigger rules for Qradar*

## Usage example
### Sigma CLI
You can quickly convert a single rule or rules in a directory structure using Sigma CLI. You can use:
Qradar Backend Extension
```
sigma convert -t qradar -f extension -o rules-extension.zip tests/files/sigma_rule.yml
```
Qradar AQL -> Default
```
sigma convert -t qradar tests/files/sigma_rule.yml
```
## Limitations and Constraints
The Qradar Backend now just support only Windows product.


**Recommend testing extensions in UAT or Dev/test enviroments**
