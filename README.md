 <!--
  Copyright 2017-present Sonatype, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
# nexus-iq-confluence-connector

# Table Of Contents
* [Introduction](#introduction)
* [Installation](#installation)
* [Usage](#usage)
  * [Configuration](#configuration)
* [The Fine Print](#the-fine-print)
* [Getting help](#getting-help)

## Introduction

`nexus-iq-confluence-connector` feeds Nexus IQ scan results into formatted Confluence pages

## Installation

```
go build
```

## Usage

Takes a webhook from IQ server makes various API calls to get to the report data.
You can then use a template to format the data before it is sent to Confluence as a new page.

This is the data availible:
```type ReportContent struct {
     Components []struct {
         Hash                string `json:"hash"`
         ComponentIdentifier struct {
             Format      string `json:"format"`
             Coordinates struct {
                 ArtifactID string `json:"artifactId"`
                 Classifier string `json:"classifier"`
                 Extension  string `json:"extension"`
                 GroupID    string `json:"groupId"`
                 Version    string `json:"version"`
             } `json:"coordinates"`
         } `json:"componentIdentifier"`
         Proprietary bool     `json:"proprietary"`
         MatchState  string   `json:"matchState"`
         Pathnames   []string `json:"pathnames"`
         LicenseData struct {
             DeclaredLicenses []struct {
                 LicenseID   string `json:"licenseId"`
                 LicenseName string `json:"licenseName"`
             } `json:"declaredLicenses"`
             ObservedLicenses []struct {
                 LicenseID   string `json:"licenseId"`
                 LicenseName string `json:"licenseName"`
             } `json:"observedLicenses"`
             OverriddenLicenses      []interface{} `json:"overriddenLicenses"`
             Status                  string        `json:"status"`
             EffectiveLicenseThreats []struct {
                 LicenseThreatGroupName     string `json:"licenseThreatGroupName"`
                 LicenseThreatGroupLevel    int    `json:"licenseThreatGroupLevel"`
                 LicenseThreatGroupCategory string `json:"licenseThreatGroupCategory"`
             } `json:"effectiveLicenseThreats"`
         } `json:"licenseData"`
         SecurityData struct {
             SecurityIssues []struct {
                 Source         string      `json:"source"`
                 Reference      string      `json:"reference"`
                 Severity       float64     `json:"severity"`
                 Status         string      `json:"status"`
                 URL            interface{} `json:"url"`
                 ThreatCategory string      `json:"threatCategory"`
             } `json:"securityIssues"`
         } `json:"securityData"`
     } `json:"components"`
     MatchSummary struct {
         TotalComponentCount int `json:"totalComponentCount"`
         KnownComponentCount int `json:"knownComponentCount"`
     } `json:"matchSummary"`
 }
 ```

### Configuration

A few example templates are included to show how to create reports.

Edit the config file to point to your IQ server, configure the Confluence setting including Space ID and tell it which template you want to use.
Set up an Application analysis webhook in IQ to notify the connector of new scans, start it up and you should be good to go.

## The Fine Print

It is worth noting that this is **NOT SUPPORTED** by Sonatype, and is a contribution of ours
to the open source community (read: you!)

Remember:

* Use this contribution at the risk tolerance that you have
* Do NOT file Sonatype support tickets related to Webpack support
* DO file issues here on GitHub, so that the community can pitch in

Phew, that was easier than I thought. Last but not least of all:

Have fun creating and using this plugin, we are glad to have you here!

## Getting help

Looking to contribute to our code but need some help? There's a few ways to get information:

* Chat with us on [Gitter](https://gitter.im/sonatype/nexus-developers)
* Connect with [@sonatypeDev](https://twitter.com/sonatypedev) on Twitter
