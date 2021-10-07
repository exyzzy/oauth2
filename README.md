# OAuth2

OAuth 2.0 client package for Go


See Medium article:
* OAuth 2.0 in Go

https://levelup.gitconnected.com/oauth-2-0-in-go-846b257d32b4

However, this is just the core oauth2 package the example that shows how to use it is at github.com/exyzzy/oclient2

## To Install:

```
go get github.com/exyzzy/oauth2
go get github.com/exyzzy/oclient2
go install $GOPATH/src/github.com/exyzzy/oclient2
```

## Legacy Notes:

* oauth2.go is the library, services.json is the config file for the services. Everything else in oclient2 is an example of how to use it.
* First you'll need to copy services.json to your client and edit it to match the services for which you have set up api accounts. Look at the curent examples, for these services you will only need to set the client_id and client_secret
For production do not include these in src code, but instead serve them from host env variables. Depending on the api you need you may have to adjust the scope. The redirect_uri is set for localhost, change this to your server when you deploy.

* You may wish to adjust consts: GcPeriod, InitAuthTimeout, MaxState (see oauth2.go)

* See main.go and templates/home.html for an example of how to set up the redirect link and authorization requests.

* See main.go and templates/api.html for an example of how to set up the service api requests.


## To use: (see oclient2 example)

copy services.json to your project, edit it, set up environment variables

```
main.go:
import "github.com/exyzzy/oauth2"
func main() {
    err := oauth2.InitOauth2("services.json")
    if err != nil {
        log.Fatal(err)
    }
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    r := mux.NewRouter()
	r.HandleFunc("/login/{authtype}/{service}", LoginHandler)
    r.HandleFunc("/redirect", RedirectHandler)
	r.HandleFunc("/google/get/user", GoogleGetUserHandler)
	http.Handle("/", r)
    fmt.Println(">>>>>>> Client started at:", port)
    log.Fatal(http.ListenAndServe(":"+port, nil))
    return
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	authtype := vars["authtype"]
	service := vars["service"]
	authlink := oauth2.AuthLink(r, authtype, service)
	http.Redirect(w, r, authlink, http.StatusTemporaryRedirect)
}

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
    m, err := url.ParseQuery(r.URL.RawQuery)
    if err != nil {
        fmt.Println("Redirect Error: ", r.URL.RawQuery, err.Error())
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    code := m.Get("code")
    state := m.Get("state")
    err = oauth2.ExchangeCode(w, r, code, state) //do not write to w before this call
    if err != nil {
        http.Error(w, "Exchange Failed: "+err.Error(), http.StatusInternalServerError)
        return
    }
    // fmt.Fprintln(w, "Code: ", code, " Scope: ", scope)
    http.Redirect(w, r, "/page/api", 302)
}

func processAPI(w http.ResponseWriter, r *http.Request, service string, action string, url string, data map[string]interface{}) (result string, err error) {
	resp, err := oauth2.ApiRequest(w, r, service, action, url, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result = string(body)
	return
}

func GoogleGetUserHandler(w http.ResponseWriter, r *http.Request) {
	url := "https://www.googleapis.com/oauth2/v3/userinfo"
	result, err := processAPI(w, r, oauth2.GOOGLE, "GET", url, nil)
	if err == nil {
		fmt.Fprintln(w, result)
	}
}

home.html:
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>OClient</title>
            <style>
                body {
                background-color: lightgray;
                }
            </style>
            
        </head>
        <body>
            <h1>OClient Authorize</h1>
            <br>
            <button onclick="window.location.href=window.location.origin + '/login/secret/google'">Authorize Google</button>
        </body>
    </html>
```
