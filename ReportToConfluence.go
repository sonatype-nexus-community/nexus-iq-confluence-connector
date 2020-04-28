package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"sonatypeWebhook"
	"strconv"
	"time"

	"github.com/adamjwsuch/go-confluence"
	"github.com/jinzhu/configor"
)

const (
	path                      = "/"
	sessionAPI         string = "rest/user/session"
	applicationsAPI    string = "/api/v2/applications"
	applicationsReport string = "/api/v2/reports/applications/"
)

type auth struct {
	username, password string
}

type serverInfo struct {
	url            string
	auth           *auth
	csrfProtection bool
}

type Config struct {
	Template string `default:"policy-violations.html"`
	IQ       struct {
		URL              string `required:"true"`
		User             string `required:"true"`
		Password         string `required:"true"`
		NoCsrfProtection bool   `default:false`
	}
	Webhook struct {
		Secret string
		Port   uint `default:"3001"`
	}
	Confluence struct {
		URL        string `required:"true"`
		User       string `required:"true"`
		Password   string `required:"true"`
		Spacekey   string `required:"true"`
		Basepageid string
	}
	Verbose bool `default:false`
}

var verbose *bool

func main() {
	configfile := flag.String("configfile", "config.yml", "Location of the config file (default: config.yml)")
	verbose = flag.Bool("verbose", false, "Enables/disables verbose debugging output (default: false)")
	flag.Parse()

	config := Config{}
	err := configor.Load(&config, *configfile)
	if err != nil {
		fmt.Printf("Config file error %v", err)
		os.Exit(0)
	}

	if !*verbose {
		if config.Verbose {
			*verbose = true //Can be set by command line arg or config file
		}
	}

	if *verbose {
		fmt.Printf("Config: %v\n", PrettyPrint(config))
	}

	server := &serverInfo{
		url:            config.IQ.URL,
		auth:           &auth{username: config.IQ.User, password: config.IQ.Password},
		csrfProtection: config.IQ.NoCsrfProtection,
	}

	var hook *sonatypeWebhook.Webhook
	//var err error
	if config.Webhook.Secret != "" {
		hook, err = sonatypeWebhook.New(sonatypeWebhook.Options.Secret(config.Webhook.Secret))
	} else {
		hook, err = sonatypeWebhook.New()
	}
	if err != nil {
		fmt.Printf("Error creating webhook: %+v\n", err)
		os.Exit(0)
	}

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		payload, err := hook.Parse(r, sonatypeWebhook.PolicyManagement, sonatypeWebhook.ApplicationEvaluation, sonatypeWebhook.LicenseOverrideManagement, sonatypeWebhook.SecurityVulnerabilityOverrideManagement)
		if err != nil {
			if err == sonatypeWebhook.ErrEventNotFound {
				fmt.Printf("Requested event not recognised %+v\n", err)
			} else {
				fmt.Printf("Webhook error: %+v\n", err)
			}
		}
		switch payload.(type) {

		case sonatypeWebhook.ApplicationEvaluationPayload:
			AppEval := payload.(sonatypeWebhook.ApplicationEvaluationPayload)
			if *verbose {
				fmt.Printf("Webhook payload: %v\n", PrettyPrint(AppEval))
			}
			pubAppID, AppName, err := server.appIDToPubAppID(AppEval.ApplicationEvaluation.OwnerId)
			if err != nil {
				fmt.Printf("Error fetching Application Public ID: %+v", err)
				if *verbose {
					fmt.Printf("OwnerID: %+v\n", AppEval.ApplicationEvaluation.OwnerId)
				}
				return
			}
			if *verbose {
				fmt.Printf("Successfully fetched AppID: %+v\n", pubAppID)
			}
			AppReport, HtmlReport, err := server.AppIDToReports(AppEval.ApplicationEvaluation.OwnerId, AppEval.ApplicationEvaluation.Stage)
			if err != nil {
				fmt.Printf("Error fetching Reports: %+v\n", err)
				return
			}
			if *verbose {
				fmt.Printf("Successfully fetched Report: %+v\n", AppReport)
			}
			ReportContent, err := server.Report(AppReport)
			if err != nil {
				fmt.Printf("Error fetching Report: %+v\n", err)
				return
			}
			ReportContent.ReportLink = server.url + "/" + HtmlReport
			ReportContent.Stage = AppEval.ApplicationEvaluation.Stage
			ReportContent.AppName = AppName
			report, err := reportFromTemplate(ReportContent)
			if err != nil {
				fmt.Printf("%v\n", err)
				return
			}
			reportName := "Application: " + ReportContent.AppName + " - Stage: " + ReportContent.Stage
			err = exportToConfluence(report, reportName, config)
			if err != nil {
				fmt.Printf("%v\n", err)
				return
			}

		case sonatypeWebhook.PolicyManagementPayload:
			fmt.Println("Policy Management webhook not supported")
			return

		case sonatypeWebhook.LicenseOverrideManagementPayload:
			fmt.Println("License Override Management webhook not supported")
			return

		case sonatypeWebhook.SecurityVulnerabilityOverrideManagementPayload:
			fmt.Println("Security Vulnerability Override  webhook not supported")
			return
		}
	})
	fmtPort := strconv.FormatUint(uint64(config.Webhook.Port), 10)
	fmt.Println("Waiting for connections on port ", fmtPort)
	err = http.ListenAndServe(":"+fmtPort, nil)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
	fmt.Println("Completed")
}

func PrettyPrint(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "\t")
	if err == nil {
		return string(b)
	}
	return "Pretty print error"
}

func reportFromTemplate(report *ReportContent) (string, error) {
	t, err := template.ParseFiles("policy-violations.html")
	if err != nil {
		return "", errors.New("error rendering template")
	}
	var tpl bytes.Buffer
	t.Execute(&tpl, report)
	return tpl.String(), nil
}

func exportToConfluence(pageContent string, pageName string, config Config) error {
	auth := confluence.BasicAuth(config.Confluence.User, config.Confluence.Password)
	wiki, err := confluence.NewWiki(config.Confluence.URL, auth)
	//wiki.verbose = true
	if err != nil {
		//return errors.New("error connecting to Confluence: ", err)
		return err
	}

	var content confluence.Content
	content.Type = "page"
	content.Title = pageName + " " + time.Now().Format("2006-01-02 15:04:05")
	content.Space.Key = config.Confluence.Spacekey //Note this is the short Confluence Key not the full space name
	content.Version.Number = 1
	content.Body.Storage.Value = pageContent
	content.Body.Storage.Representation = "storage"
	if config.Confluence.Basepageid != "" { //Only use if provided, otherwise just gets put at root level
		content.Ancestors = append(content.Ancestors, confluence.ContentAncestor{ID: config.Confluence.Basepageid})
	}

	_, _, err = wiki.CreateContent(&content)
	if err != nil {
		return err
	}
	return nil
}

func (server *serverInfo) apiCall(URL string) ([]byte, error) {
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(server.auth.username, server.auth.password)

	if server.csrfProtection {
		var token *http.Cookie
		token, err = sessionToken(server)
		req.Header.Set("X-CSRF-TOKEN", token.Value)
		req.AddCookie(token)
		// log.Printf("Using token: %s\n", token.Value)
	}

	var resp *http.Response
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	} else {
		payload, err := ioutil.ReadAll(resp.Body)
		return payload, err
	}
}

func (server *serverInfo) appIDToPubAppID(pubAppID string) (string, string, error) {
	//Call to /api/v2/applications
	if *verbose {
		fmt.Printf("Applications URL: %+v%+v/%+v\n", server.url, applicationsAPI, pubAppID)
	}
	payload, err := server.apiCall(server.url + applicationsAPI + "/" + pubAppID)
	if err != nil {
		return "", "", err
	}
	if *verbose {
		fmt.Printf("Applications response payload: %v\n", PrettyPrint(string(payload[:])))
	}
	var pl *applications
	err = json.Unmarshal(payload, &pl)
	if err != nil {
		return "", "", err
	}
	if pl == nil {
		return "", "", errors.New("No application respose payload")
	}
	return pl.PublicID, pl.Name, err
}

type applications struct {
	ID              string `json:"id"`
	PublicID        string `json:"publicid"`
	ApplicationID   string `json:"applicationId"`
	Name            string `json:"name"`
	OrganizationId  string `json:"organizationId"`
	ContactUserName string `json:"contactUserName"`
	//ApplicationTags []struct {
	//	ID            string `json:"id"`
	//	TagID         string `json:"tagId"`
	//	ApplicationID string `json:"applicationId"`
	//} `json:"applicationTags"`
}

func (server *serverInfo) AppIDToReports(AppID string, buildStage string) (string, string, error) {
	//Call to /api/v2/reports/applications/{id}
	if *verbose {
		fmt.Printf("Application report URL: %+v%+v%+v\n", server.url, applicationsReport, AppID)
	}
	payload, err := server.apiCall(server.url + applicationsReport + AppID)
	if err != nil {
		return "", "", err
	}
	if *verbose {
		fmt.Printf("Application report response payload: %v\n", PrettyPrint(string(payload[:])))
	}
	var pl reports
	err = json.Unmarshal(payload, &pl)
	for _, elem := range pl {
		if elem.Stage == buildStage {
			return elem.ReportDataUrl, elem.ReportHtmlUrl, err
		}
	}
	return "", "", errors.New("Stage not found for application")
}

type reports []struct {
	Stage         string `json:"stage"`
	ReportDataUrl string `json:"reportDataUrl"`
	ReportHtmlUrl string `json:"reportHtmlUrl"`
}

func (server *serverInfo) Report(reportURL string) (*ReportContent, error) {
	//Call to "reportDataUrl" from Reports call
	if *verbose {
		fmt.Printf("Report URL: %+v/%+v\n", server.url, reportURL)
	}
	payload, err := server.apiCall(server.url + "/" + reportURL)
	if err != nil {
		return nil, err
	}
	var pl ReportContent
	err = json.Unmarshal(payload, &pl)
	if *verbose && err == nil {
		fmt.Printf("Report response payload: %v\n", PrettyPrint(pl))
	}
	return &pl, err
}

func (server *serverInfo) LicenseInfo(appID string, pubAppID string) (*licenseContent, error) {
	//Call to "reportDataUrl" from Reports call
	LicenseReport := server.url + "/rest/report/" + pubAppID + "/" + appID + "/browseReport/licenses.json"
	if *verbose {
		fmt.Printf("License report URL: %+v\n", LicenseReport)
	}
	payload, err := server.apiCall(LicenseReport)
	if err != nil {
		return nil, err
	}
	var pl licenseContent
	err = json.Unmarshal(payload, &pl)
	if *verbose && err == nil {
		fmt.Printf("License response payload: %v\n", PrettyPrint(pl))
	}
	return &pl, err
}

type ReportContent struct {
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
	ReportLink string
	Stage      string
	AppName    string
}

type licenseContent struct {
	Data []struct {
		ComponentIdentifier []struct {
			Format      string `json:"format"`
			Coordinates []struct {
				ArtifactId string `json:"artifactId"`
				Classifier string `json:"classifier"`
				Extension  string `json:"extension"`
				GroupId    string `json:"groupId"`
				Version    string `json:"version"`
			} `json:"coordinates"`
		} `json:"componentIdentifier"`
		GroupID           string   `json:"groupId"`
		ArtifactID        string   `json:"artifactId"`
		Version           string   `json:"version"`
		Hash              string   `json:"hash"`
		DeclaredLicenses  []string `json:"declaredLicenses"`
		ObservedLicenses  []string `json:"observedLicenses"`
		EffectiveLicenses []string `json:"effectiveLicenses"`
		SecurityCounters  struct {
			Critical int `json:"Critical"`
			Severe   int `json:"Severe"`
			Moderate int `json:"Moderate"`
		} `json:"securityCounters"`
		EffectiveLicenseThreat int     `json:"effectiveLicenseThreat"`
		MatchState             string  `json:"matchState"`
		Proprietary            bool    `json:"proprietary"`
		SecurityThreatLevel    float64 `json:"securityThreatLevel"`
		CatalogDate            int64   `json:"catalogDate"`
		DisplayName            struct {
			Parts []struct {
				Field string `json:"field,omitempty"`
				Value string `json:"value"`
			} `json:"parts"`
		} `json:"displayName"`
	} `json:"aaData"`
}

func sessionToken(server *serverInfo) (token *http.Cookie, err error) {
	url := server.url + "/" + sessionAPI

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req.SetBasicAuth(server.auth.username, server.auth.password)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		panic(resp.Status)
	} else {
		for _, element := range resp.Cookies() {
			if element.Name == "CLM-CSRF-TOKEN" {
				token = element
			}
		}
	}

	return token, err
}
