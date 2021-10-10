// Package oauth2 is a small and simple oauth 2 library in go. Also see https://github.com/exyzzy/oclient2, and the Medium article, "OAuth 2.0 in Go"
package oauth2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//Services currently tested, the consts are not necessary
const (
	STRAVA   = "strava"
	LINKEDIN = "linkedin"
	SPOTIFY  = "spotify"
	GITHUB   = "github"
	FITBIT   = "fitbit"
	OURA     = "oura"
	GOOGLE   = "google"
	AMAZON   = "amazon"
	WITHINGS = "withings"
)

// Service keys
const (
	AUTHORIZE = "authorization_code"
	REFRESH   = "refresh_token"
	SECRET    = "secret"
	PKCE      = "pkce"
)

// InitOauth2 initializes PKCE and loads services.json, it should be called before using the package. Services.json should be copied to your project and edited there.
func InitOauth2(servicesFile string) error {
	pkceInit()
	return loadConfig(servicesFile, &services)
}

//== Services

var services map[string]map[string]string

func loadConfig(fname string, config *map[string]map[string]string) (err error) {
	file, err := os.Open(fname)
	if err != nil {
		return
	}
	defer file.Close()
	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	json.Unmarshal([]byte(byteValue), config)
	for k, v := range *config {
		v["client_id"] = os.Getenv(v["client_id"])
		if v["client_id"] == "" {
			v["client_id"] = "MISSING"
			fmt.Println("missing service client_id for " + k)
			//don't block on missing client entry
			// err = errors.New("missing service client_id for " + k)
			// return
		}
		v["client_secret"] = os.Getenv(v["client_secret"])
		if v["client_secret"] == "" {
			v["client_secret"] = "MISSING"
			fmt.Println("missing service client_secret for " + k)
			//don't block on missing client entry
			// err = errors.New("missing service client_id for " + k)
			// return
		}
	}
	return
}

//== PKCE

func pkceInit() {
	rand.Seed(time.Now().UnixNano())
}

//string of pkce allowed chars
func pkceVerifier(length int) string {
	if length > 128 {
		length = 128
	}
	if length < 43 {
		length = 43
	}
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

//base64-URL-encoded SHA256 hash of verifier, per rfc 7636
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
	return (challenge)
}

//== State Management

// Tunable params for state management.
const (
	GcPeriod        = 60  //minutes - minimum ideal time between GC runs (unless MaxState)
	InitAuthTimeout = 10  //minutes - amount of time user has to complete Authorization and get Access Code from Authorization Server
	MaxState        = 400 //max allowed length of state map, to prevent malicious memory overflow
)

type state struct {
	CreatedAt     time.Time
	Service       string
	AuthType      string
	PkceVerifier  string
	PkceChallenge string
}

var stateMap = make(map[string]*state)
var lastGc = time.Now().UTC()
var mutex = &sync.Mutex{}

//get the payload for a state, check expiration, and delete
func getState(key string) (value *state) {
	mutex.Lock()
	v, exists := stateMap[key]
	if exists {
		n := time.Now().UTC()
		if n.After(v.CreatedAt.Add(InitAuthTimeout * time.Minute)) {
			value = nil //don't accept expired state
		} else {
			value = v
		}
		delete(stateMap, key)
	} else {
		value = nil
	}
	defer mutex.Unlock()
	return
}

//set the payload for a state, set expiration, do gc as needed
func setState(key string, value *state) {
	mutex.Lock()
	n := time.Now().UTC()
	value.CreatedAt = n
	stateMap[key] = value
	//gc
	authTimeout := InitAuthTimeout * time.Minute //type Duration
	gcTime := lastGc.Add(GcPeriod * time.Minute)
	if n.After(gcTime) || len(stateMap) >= MaxState {
		for ok := true; ok; ok = len(stateMap) >= MaxState { //keep going till below MaxState, 1/2 each cycle
			for k, v := range stateMap {
				expiresAt := v.CreatedAt.Add(authTimeout)
				if n.After(expiresAt) {
					delete(stateMap, k)
				}
			}
			authTimeout /= 2
		}
		lastGc = time.Now().UTC()
	}
	defer mutex.Unlock()
}

//== Cookie Helpers

// Prefix for cookie name, the service name from services.json will be appended.
const CookiePrefix = "_Oauth2"

func cookieName(service string) string {
	return (CookiePrefix + service)
}

// SetCookie is a generic cookie setter.
func SetCookie(w http.ResponseWriter, token string, cookieName string) {
	tok64 := base64.StdEncoding.EncodeToString([]byte(token))
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    tok64,
		HttpOnly: true,
		Secure:   false, //use true for production
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
}

// GetCookie is a generic cookie getter.
func GetCookie(r *http.Request, cookieName string) (token string, err error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	tokb, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return
	}
	token = string(tokb)
	return
}

//== API Helpers

// AuthLink builds the service Code Authorize Link and saves the state as pkceVerifier (128).
func AuthLink(r *http.Request, authtype string, service string) (result string) {
	stData := state{Service: service, AuthType: authtype}
	st := pkceVerifier(128)
	result = services[service]["authorize_endpoint"]
	result += "?client_id=" + services[service]["client_id"]
	result += "&response_type=code&redirect_uri="
	result += url.QueryEscape(services[service]["redirect_uri"])
	result += "&scope=" + services[service]["scope"]
	result += services[service]["prompt"]
	if authtype == PKCE {
		stData.PkceVerifier = pkceVerifier(128)
		stData.PkceChallenge = pkceChallenge(stData.PkceVerifier)
		result += "&code_challenge=" + stData.PkceChallenge
		result += "&code_challenge_method=S256"
	}
	result += "&state=" + st
	// result = url.QueryEscape(result)
	setState(st, &stData)
	fmt.Println("Authorize Link: ", result)
	return
}

// GetUser calls the user_endpoint api if one is included in services.json to get user profile data. The scope must allow this.
func GetUser(w http.ResponseWriter, r *http.Request, service string) (result map[string]interface{}, err error) {
	userEndpoint, ok := services[service]["user_endpoint"]
	if !ok || userEndpoint == "" {
		err = errors.New("no user endpoint")
		return
	}
	resp, err := ApiRequest(w, r, service, "GET", userEndpoint, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	bs := string(body)
	err = json.Unmarshal([]byte(bs), &result)
	return
}

//ApiRequest makes a call to a resource api, adding oauth bearer token to the header. It automatically refreshes the token if it is expired. Seervice is the name of the service as defined in services.json, like 'google". Method is the http method, like "POST" or "GET". Url is the url for the api.
func ApiRequest(w http.ResponseWriter, r *http.Request, service, method, url string, data map[string]interface{}) (response *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	var body io.Reader
	if data == nil {
		body = nil
	} else {
		var requestBody []byte
		requestBody, err = json.Marshal(data)
		if err != nil {
			return
		}
		body = bytes.NewBuffer(requestBody)
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return
	}
	err = setHeader(w, r, service, request)
	if err != nil {
		err = errors.New("unable to set Header (" + service + "): " + err.Error())
		return
	}
	response, err = client.Do(request)
	return
}

func epochSeconds() int64 {
	now := time.Now()
	secs := now.Unix()
	return secs
}

//get Access Token via cookie, refresh if expired, set header bearer token
func setHeader(w http.ResponseWriter, r *http.Request, service string, newReq *http.Request) (err error) {
	token, err := GetCookie(r, cookieName(service))
	if err != nil {
		return
	}
	var tokMap map[string]interface{}

	// err = json.Unmarshal([]byte(token), &tokMap)
	// normally as above, but we want numbers as ints vs floats
	decoder := json.NewDecoder(strings.NewReader(token))
	decoder.UseNumber()
	err = decoder.Decode(&tokMap)
	if err != nil {
		return
	}
	expiresAt, err := tokMap["expires_at"].(json.Number).Int64()
	if err != nil {
		return
	}
	if epochSeconds() > expiresAt { //token has expired, refresh it
		if services[service]["refresh_allowed"] == "false" {
			err = errors.New("non-refreshable token expired, re-authorize")
			return
		}
		refresh, exists := tokMap["refresh_token"]
		if !exists {
			err = errors.New("refresh Token Not Found")
			return
		}
		var newToken string
		newToken, err = getToken(w, r, service, REFRESH, refresh.(string), SECRET, "")
		if err != nil {
			return
		}
		SetCookie(w, newToken, cookieName(service)) //note: must set cookie before writing to responsewriter
		decoder = json.NewDecoder(strings.NewReader(newToken))
		decoder.UseNumber()
		tokMap = make(map[string]interface{})
		err = decoder.Decode(&tokMap)
		if err != nil {
			return
		}
	}
	newReq.Header.Add("Authorization", "Bearer "+tokMap["access_token"].(string))
	newReq.Header.Set("Content-Type", "application/json")
	newReq.Header.Set("Accept", "application/json")
	return
}

//== Access Token

//ExchangeCode is used by the redirect handler to exchange the Authorization Code for an Access Token.
func ExchangeCode(w http.ResponseWriter, r *http.Request, code string, state string) (err error) {
	statePtr := getState(state)
	if statePtr == nil {
		err = errors.New("state Key not found")
		return
	}
	token, err := getToken(w, r, statePtr.Service, AUTHORIZE, code, statePtr.AuthType, statePtr.PkceVerifier)
	if err != nil {
		return
	}
	SetCookie(w, token, cookieName(statePtr.Service)) //note: must set cookie before writing to responsewriter
	return
}

//wrapper to set accept header
func jsonPost(url string, body io.Reader) (resp *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func basicPost(url string, body io.Reader, ba string) (resp *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Basic "+ba)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

// Small delta subtracted from exires_at conversion to account for transport time.
const DELTASECS = 5

//get a token from authorization endpoint
func getToken(w http.ResponseWriter, r *http.Request, service string, tokType string, code string, authType string, verifier string) (result string, err error) {
	rParams := map[string]string{
		"client_id":    services[service]["client_id"],
		"redirect_uri": services[service]["redirect_uri"],
		"action":       "requesttoken", //withings
	}

	switch tokType {
	case AUTHORIZE:
		rParams["code"] = code
		rParams["grant_type"] = AUTHORIZE
	case REFRESH:
		rParams["refresh_token"] = code
		rParams["grant_type"] = REFRESH
	default:
		err = errors.New("unknown tokType")
		return
	}
	switch authType {
	case SECRET:
		rParams["client_secret"] = services[service]["client_secret"]
	case PKCE:
		rParams["code_verifier"] = verifier
	default:
		err = errors.New("unknown authType")
		return
	}
	var resp *http.Response
	switch services[service]["post_type"] {
	case "basic":
		form := url.Values{}
		for k, v := range rParams {
			form.Set(k, v)
		}

		basic := basicAuth(rParams["client_id"], rParams["client_secret"])

		resp, err = basicPost(services[service]["token_endpoint"], strings.NewReader(form.Encode()), basic)
		if err != nil {
			return
		}
	case "json":
		var requestBody []byte
		requestBody, err = json.Marshal(rParams)
		if err != nil {
			return
		}
		resp, err = jsonPost(services[service]["token_endpoint"], bytes.NewBuffer(requestBody))
		if err != nil {
			return
		}

	case "form":
		vals := url.Values{}
		for k, v := range rParams {
			vals.Set(k, v)
		}
		resp, err = http.PostForm(services[service]["token_endpoint"], vals)
		if err != nil {
			return
		}
	default:
		err = errors.New("unknown post_type")
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(string(body))
		return
	}
	//check for expires_at
	var tokMap map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	err = decoder.Decode(&tokMap)
	if err != nil {
		err = errors.New("decoder.Decode: " + err.Error())
		return
	}

	//withings oauth adds an outer "body" which must be stripped off
	_, exists := tokMap["body"]
	if exists {
		tokMap = tokMap["body"].(map[string]interface{})
	}

	//if no access
	_, exists = tokMap["access_token"]
	if !exists {
		err = errors.New("Missing access_token: " + string(body))
		return
	}

	_, exists = tokMap["expires_at"]
	if !exists {
		var expiresIn int64
		expire, exists := tokMap["expires_in"]
		if !exists { //no expiration, so make it a year
			expiresIn = 31536000
		} else {
			expiresIn, err = expire.(json.Number).Int64()
		}
		tokMap["expires_at"] = epochSeconds() + expiresIn - DELTASECS
	}

	b, err := json.Marshal(tokMap)
	if err != nil {
		err = errors.New("json.Marshal: " + err.Error())
		return
	}
	result = string(b)
	fmt.Println("completed getToken: ", rParams["grant_type"])
	return
}
