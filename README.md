# nexus-iq-confluence-connector
Feed Nexus IQ scan results into formatted Confluence pages

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

 A few example templates are included to show how to create reports.
