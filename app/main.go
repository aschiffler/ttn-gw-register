package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	oauthConfig  = &oauth2.Config{}
	store        = sessions.NewCookieStore([]byte("4711081508154711"))
	frequencyMap = make(map[string]FrequencyPlan)
)

type PageData struct {
	Message    string
	ButtonText string
	FreqMap    map[string]FrequencyPlan
	CupsKey    string
	Lns        string
}

type ApiKeyResponse struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Rights    []string  `json:"rights"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AssignGwKey struct {
	Gateway struct {
		LbsLnsSecret struct {
			Value string `json:"value"`
		} `json:"lbs_lns_secret"`
	} `json:"gateway"`
	FieldMask struct {
		Paths []string `json:"paths"`
	} `json:"field_mask"`
}

type AuthInfo struct {
	OauthAccessToken struct {
		UserIds struct {
			UserID string `json:"user_id"`
		} `json:"user_ids"`
		UserSessionID string `json:"user_session_id"`
		ClientIds     struct {
			ClientID string `json:"client_id"`
		} `json:"client_ids"`
		ID        string    `json:"id"`
		Rights    []string  `json:"rights"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"oauth_access_token"`
	UniversalRights struct {
		Rights []string `json:"rights"`
	} `json:"universal_rights"`
	IsAdmin bool `json:"is_admin"`
}

type GatewayRegistration struct {
	Gateway struct {
		GatewayServerAddress string `json:"gateway_server_address" default:""`
		EnforceDutyCycle     bool   `json:"enforce_duty_cycle" default:"false"`
		ScheduleAnytimeDelay string `json:"schedule_anytime_delay" default:"0.530s"`
		Ids                  struct {
			Eui       string `json:"eui"`
			GatewayID string `json:"gateway_id"`
		} `json:"ids"`
		Name                           string   `json:"name"`
		FrequencyPlanIds               []string `json:"frequency_plan_ids"`
		RequireAuthenticatedConnection bool     `json:"require_authenticated_connection" default:"true"`
		StatusPublic                   bool     `json:"status_public" default:"false"`
		LocationPublic                 bool     `json:"location_public" default:"false"`
	} `json:"gateway"`
}

type ApiKey struct {
	Name   string   `json:"name"`
	Rights []string `json:"rights"`
}

type FrequencyPlan struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	BaseFrequency int    `json:"base_frequency"`
	BandID        string `json:"band_id"`
	BaseID        string `json:"base_id,omitempty"`
}

type FrequencyPlans struct {
	FrequencyPlans []FrequencyPlan `json:"frequency_plans"`
}

type Gateways struct {
	Gateways []struct {
		Ids struct {
			GatewayID string `json:"gateway_id"`
			Eui       string `json:"eui"`
		} `json:"ids"`
		CreatedAt        time.Time `json:"created_at"`
		UpdatedAt        time.Time `json:"updated_at"`
		Name             string    `json:"name"`
		FrequencyPlanID  string    `json:"frequency_plan_id"`
		FrequencyPlanIds []string  `json:"frequency_plan_ids"`
	} `json:"gateways"`
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func createFrequencyPlan() {
	file, err := os.Open("frequency_plans.json")
	if err != nil {
		log.Fatalf("Error opening file: %s", err)
	}
	defer file.Close()

	jsonData, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %s", err)
	}

	var plans FrequencyPlans
	err = json.Unmarshal([]byte(jsonData), &plans)
	if err != nil {
		log.Fatalf("Error occurred while unmarshalling JSON: %s", err)
	}

	for _, plan := range plans.FrequencyPlans {
		frequencyMap[plan.ID] = plan
	}

}

func main() {
	// Serve static assets from the "assets" directory
	godotenv.Load()
	oauthConfig.RedirectURL = os.Getenv("OAUTH_CLIENT_CALLBACK")
	oauthConfig.ClientID = os.Getenv("OAUTH_CLIENT_ID")
	oauthConfig.ClientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
	oauthConfig.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://" + os.Getenv("LNS_DOMAIN") + "/oauth/authorize",
		TokenURL: "https://" + os.Getenv("LNS_DOMAIN") + "/oauth/token",
	}
	fs := http.FileServer(http.Dir("assets"))
	http.Handle("/assets/", http.StripPrefix("/assets/", fs))
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/post", handlePost)
	createFrequencyPlan()
	fmt.Println("Listening on "+os.Getenv("BIND"))
	fmt.Println("LNS_DOMAIN=" + os.Getenv("LNS_DOMAIN"))
	log.Fatal(http.ListenAndServe(os.Getenv("BIND"), nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-ttn-gw-register")
	data := PageData{
		Message:    r.FormValue("msg"),
		ButtonText: "Get API key",
		FreqMap:    frequencyMap,
		CupsKey:    r.FormValue("cupskey"),
		Lns:        os.Getenv("LNS_DOMAIN"),
	}
	if session.IsNew {
		fmt.Println("New session")
		store.Options.MaxAge = 60
		session.Save(r, w)
		data.ButtonText = "Get Token"
	}
	// Check if user is already logged in
	if session.Values["state"] == nil && r.FormValue("login") != "0" {
		// redirect to /login
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}
	//
	if session.Values["state"] != nil {
		data.ButtonText = "Register Gateway"
	}
	// Check the path and return 404 if it is not empty
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Render main page
	tmpl := template.Must(template.New("post").Parse(`
	<html>
	<body><center>
		<h1>LNS used: {{.Lns}}</h1>
		<form action="/post" method="post">
			<button type="submit">{{.ButtonText}}</button>
			<p></p>
			<div id=myform>
			<label for="gw_eui">Gateway EUI</label>
			<p></p>
			<input type="text" name="gw_eui"  value="" length=16>
			<p></p>
			<label for="gw_id" >Gateway ID</label>
			<p></p>
			<input type="text"  name="gw_id" value="">
			<p></p>
			<label for="freqplans" >Frequency Plan:</label>
			<p></p>
			<select name="freqplans"  >
			{{ range $key, $value := .FreqMap }}
				<option value={{$key}}>{{$value.Name}}</option>
			{{end}}
			</select>
			</div>
		</form>
	</center></body>
        <script>
            function getQueryParams() {
                let params = {};
                let queryString = window.location.search.substring(1);
                let regex = /([^&=]+)=([^&]*)/g;
                let m;
                while (m = regex.exec(queryString)) {
                    params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
                }
                return params;
            }
            function downloadTextFile(content, fileName) {
                let a = document.createElement("a");
                let file = new Blob([content], {type: "text/plain"});
                a.href = URL.createObjectURL(file);
                a.download = fileName;
                a.click();
            }
            window.onload = function() {
                let params = getQueryParams();
				if (params['show']== "1") {
					document.getElementById("myform").hidden = false;

				} else {
					document.getElementById("myform").hidden = true;

				}
                if (params['cupskey']) {
					if (params['cupskey'] != "-1") {
                    downloadTextFile("Authorization: Bearer "+params['cupskey'], "cupskey_"+params['gw_eui']+".txt");
					}
                }
				if (params['msg']) {
					alert(params['msg']);
				}
            }
        </script>
	</html>`))
	tmpl.Execute(w, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-ttn-gw-register")
	if session.IsNew {
		fmt.Println("New session")
		store.Options.MaxAge = 60
		session.Save(r, w)
	}
	// Redirect to IDP if it is a new token request to get authorization code with existing state
	if session.Values["state"] != nil {
		url := oauthConfig.AuthCodeURL(session.Values["state"].(string))
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		fmt.Println("Shall not happen, Redirecting to IDP")
		return
	}
	// New session, generate state
	state, err := generateRandomString(16)
	if err != nil {
		http.Redirect(w, r, "/?msg=🚫 Failed to generate state", http.StatusTemporaryRedirect)
		return
	}
	// Save state in session
	session.Values["state"] = state
	session.Save(r, w)
	// Redirect to IDP to get authorization code
	url := oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-ttn-gw-register")
	if session.IsNew {
		fmt.Println("New session")
		store.Options.MaxAge = 60
		session.Save(r, w)
	}
	// Invalidate old token if it exists
	if token, ok := session.Values["token"].(*oauth2.Token); ok {
		accessToken := token.AccessToken
		if accessToken != "" {
			if strings.Contains(accessToken, ".") {
				tokenID := strings.Split(accessToken, ".")[1]
				err := invalidateToken(accessToken, tokenID, session.Values["user"].(string))
				if err != nil {
					http.Redirect(w, r, "/?msg=🚫 Failed to invalidate token", http.StatusTemporaryRedirect)
					return
				}
				fmt.Println("Token ID: " + tokenID + " invalidated")
				session.Values["token"] = ""
			}
		}
	}
	// Check if state is valid
	state := r.FormValue("state")
	if state != session.Values["state"] {
		http.Redirect(w, r, "/?msg=🚫 State invalid", http.StatusTemporaryRedirect)
		return
	}
	// Get new token
	code := r.FormValue("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Redirect(w, r, "/?msg=🚫 Code exchange failed", http.StatusTemporaryRedirect)
		return
	}
	// Save token in session
	session.Values["token"] = token.AccessToken
	session.Save(r, w)
	// Get user info
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://" + os.Getenv("LNS_DOMAIN") + "/api/v3/auth_info")
	if err != nil {
		http.Redirect(w, r, "/?msg=🚫 Failed to get user info", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Redirect(w, r, "/?msg=🚫 Failed to read body", http.StatusTemporaryRedirect)
		return
	}
	// Unmarshal the JSON response
	var authInfo AuthInfo
	if err := json.Unmarshal(body, &authInfo); err != nil {
		http.Redirect(w, r, "/?msg=🚫 Failed to unmarshal JSON", http.StatusTemporaryRedirect)
		return
	}
	session.Values["user"] = authInfo.OauthAccessToken.UserIds.UserID
	session.Save(r, w)
	// Redirect to main page
	http.Redirect(w, r, "/?show=1&msg=✅ API key aquired", http.StatusTemporaryRedirect)
}

func handlePost(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-ttn-gw-register")
	if session.IsNew {
		fmt.Println("New session")
		store.Options.MaxAge = 60
		session.Save(r, w)
	}
	// Check if there is a token in the session
	if session.Values["token"] != nil {
		if accessToken, ok := session.Values["token"].(string); ok {
			if strings.Contains(accessToken, ".") {
				fmt.Println("Post with Token ID: " + strings.Split(accessToken, ".")[1])
				if accessToken == "" {
					http.Redirect(w, r, "/?login=0&msg=🚫 Token is missing", http.StatusTemporaryRedirect)
					return
				}
				// Execute API request
				ret := ""
				msg, err := registerGateway(accessToken, r.FormValue("gw_eui"), r.FormValue("gw_id"), r.FormValue("freqplans"), session.Values["user"].(string))
				if err != nil {
					http.Redirect(w, r, "/?login=0&msg=🚫 "+msg, http.StatusTemporaryRedirect)
					err = invalidateToken(accessToken, strings.Split(accessToken, ".")[1], session.Values["user"].(string))
					session.Values["state"] = nil
					session.Values["token"] = nil
					session.Save(r, w)
					if err != nil {
						http.Redirect(w, r, "/?login=0&msg=🚫 "+msg+" and failed to invalidate token", http.StatusTemporaryRedirect)
					}
					return
				}
				ret = msg
				cupskey, err := createCupsKey(accessToken, r.FormValue("gw_id"))
				if err != nil {
					http.Redirect(w, r, "/?login=0&msg=🚫 "+msg, http.StatusTemporaryRedirect)
					err = invalidateToken(accessToken, strings.Split(accessToken, ".")[1], session.Values["user"].(string))
					session.Values["state"] = nil
					session.Values["token"] = nil
					session.Save(r, w)
					if err != nil {
						http.Redirect(w, r, "/?login=0&msg=🚫 "+msg+" and failed to invalidate token", http.StatusTemporaryRedirect)
						return
					}
				}
				cupskey += "&gw_eui=" + r.FormValue("gw_eui")
				ret = msg
				lnskey, err := createLnsKey(accessToken, r.FormValue("gw_id"))
				if err != nil {
					http.Redirect(w, r, "/?login=0&msg=🚫 "+msg, http.StatusTemporaryRedirect)
					err = invalidateToken(accessToken, strings.Split(accessToken, ".")[1], session.Values["user"].(string))
					session.Values["state"] = nil
					session.Values["token"] = nil
					session.Save(r, w)
					if err != nil {
						http.Redirect(w, r, "/?login=0&msg=🚫 "+msg+" and failed to invalidate token", http.StatusTemporaryRedirect)
					}
					return
				}
				msg, err = assignGwKey(accessToken, r.FormValue("gw_id"), base64.StdEncoding.EncodeToString([]byte(lnskey)))
				if err != nil {
					http.Redirect(w, r, "/?login=0&msg=🚫 "+msg, http.StatusTemporaryRedirect)
					err = invalidateToken(accessToken, strings.Split(accessToken, ".")[1], session.Values["user"].(string))
					session.Values["state"] = nil
					session.Values["token"] = nil
					session.Save(r, w)
					if err != nil {
						http.Redirect(w, r, "/?login=0&msg=🚫 "+msg+" and failed to invalidate token", http.StatusTemporaryRedirect)
					}
					return
				}
				if err != nil {
					http.Redirect(w, r, "/?login=0&msg=🚫 "+msg, http.StatusTemporaryRedirect)
					err = invalidateToken(accessToken, strings.Split(accessToken, ".")[1], session.Values["user"].(string))
					session.Values["state"] = nil
					session.Values["token"] = nil
					session.Save(r, w)
					if err != nil {
						http.Redirect(w, r, "/?login=0&msg=🚫 "+msg+" and failed to invalidate token", http.StatusTemporaryRedirect)
					}
					return
				}
				ret = msg
				// Success; Rvoke token and redirect to main page
				err = invalidateToken(accessToken, strings.Split(accessToken, ".")[1], session.Values["user"].(string))
				session.Values["state"] = nil
				session.Values["token"] = nil
				session.Save(r, w)
				if err != nil {
					http.Redirect(w, r, "/?login=0&msg=🚫 "+ret+" and failed to invalidate token", http.StatusTemporaryRedirect)
					return
				}
				http.Redirect(w, r, "/?login=0&msg=✅ "+ret+"&cupskey="+cupskey, http.StatusTemporaryRedirect)
			}
		}
	} else {
		http.Redirect(w, r, "/?msg=🚫 Session invalid", http.StatusTemporaryRedirect)
	}
}

func assignGwKey(accessToken string, gwID string, lnsKey string) (msg string, err error) {
	client := &http.Client{}
	reqBody := AssignGwKey{}
	reqBody.Gateway.LbsLnsSecret.Value = lnsKey
	reqBody.FieldMask.Paths = []string{"lbs_lns_secret.value", "lbs_lns_secret"}
	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "Failed to marshal JSON", err
	}
	req, err := http.NewRequest("PUT", "https://"+os.Getenv("LNS_DOMAIN")+"/api/v3/gateways/"+gwID, strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return "Failed to create request", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "Failed to make request", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return "Not Authorized", err
		}
		return "Failed", err
	}
	return "New token created", nil
}

func createLnsKey(accessToken string, gwID string) (msg string, err error) {
	client := &http.Client{}
	reqBody := ApiKey{}
	rand, _ := generateRandomString(16)
	reqBody.Name = "lns-key-" + rand
	reqBody.Rights = []string{"RIGHT_GATEWAY_INFO", "RIGHT_GATEWAY_LINK"}
	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "-1", err
	}
	req, err := http.NewRequest("POST", "https://"+os.Getenv("LNS_DOMAIN")+"/api/v3/gateways/"+gwID+"/api-keys", strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return "-1", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "-1", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return "-!", err
		}
		return "-1", err
	}
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "-1", err
	}
	// Unmarshal the JSON response
	var lnsKey ApiKeyResponse
	if err := json.Unmarshal(body, &lnsKey); err != nil {
		return "-1", err
	}
	return lnsKey.Key, nil
}

func createCupsKey(accessToken string, gwID string) (msg string, err error) {
	client := &http.Client{}
	reqBody := ApiKey{}
	rand, _ := generateRandomString(16)
	reqBody.Name = "cups-key-" + rand
	reqBody.Rights = []string{"RIGHT_GATEWAY_INFO", "RIGHT_GATEWAY_SETTINGS_BASIC", "RIGHT_GATEWAY_READ_SECRETS"}
	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "-1", err
	}
	req, err := http.NewRequest("POST", "https://"+os.Getenv("LNS_DOMAIN")+"/api/v3/gateways/"+gwID+"/api-keys", strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return "-1", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "-1", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return "Not Authorized", err
		}
		return "-1", err
	}
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "-1", err
	}
	// Unmarshal the JSON response
	var cupsKey ApiKeyResponse
	if err := json.Unmarshal(body, &cupsKey); err != nil {
		return "-1", err
	}
	return cupsKey.Key, nil
}

func registerGateway(accessToken string, gwEUI string, gwID string, freqPlan string, userID string) (msg string, err error) {
	client := &http.Client{}
	reqBody := GatewayRegistration{}
	reqBody.Gateway.Ids.Eui = gwEUI
	reqBody.Gateway.Ids.GatewayID = gwID
	reqBody.Gateway.Name = gwID + " Registered by ttn-gw-register App"
	reqBody.Gateway.FrequencyPlanIds = []string{freqPlan}
	reqBody.Gateway.RequireAuthenticatedConnection = true
	reqBody.Gateway.StatusPublic = false
	reqBody.Gateway.LocationPublic = false
	reqBody.Gateway.GatewayServerAddress = os.Getenv("LNS_DOMAIN") + ":443"
	reqBody.Gateway.EnforceDutyCycle = false
	reqBody.Gateway.ScheduleAnytimeDelay = "0.530s"
	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "Failed to marshal JSON", err
	}
	req, err := http.NewRequest("POST", "https://"+os.Getenv("LNS_DOMAIN")+"/api/v3/users/"+userID+"/gateways", strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return "Failed to create request", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "Failed to make request", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return "Not Authorized", err
		}
		return "Failed", err
	}
	return "New gateway registered", nil
}

func listGateways(accessToken string, userID string) (msg string, err error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://"+os.Getenv("LNS_DOMAIN")+"/api/v3/gateways?collaborator.user_ids.user_id="+userID, nil)
	if err != nil {
		return "Failed to create request", err
	}
	// Set the authorization header and execute the request
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return "Failed to make request", err
	}
	defer resp.Body.Close()
	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return "Not Authorized", err
		}
		return "Failed", err
	}
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Failed to read body", err
	}
	// Unmarshal the JSON response
	var gateways Gateways
	if err := json.Unmarshal(body, &gateways); err != nil {
		return "Failed to unmarshal JSON", err
	}
	// concatenate all gateway IDs and seperated by a comma
	var gwIDs string
	gwIDs = "Your GWs: "
	for _, gw := range gateways.Gateways {
		gwIDs += gw.Ids.GatewayID + "%20"
	}
	return gwIDs, nil
}

func invalidateToken(accessToken string, tokenID string, userID string) error {
	client := &http.Client{}
	req, err := http.NewRequest("DELETE", "https://"+os.Getenv("LNS_DOMAIN")+"/api/v3/users/"+userID+"/authorizations/ttn-gw-register/tokens/"+tokenID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var response interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}
	if response.(map[string]interface{})["message"] != nil {
		return errors.New(response.(map[string]interface{})["message"].(string))
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return err
	}
	return nil
}
