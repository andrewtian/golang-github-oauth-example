package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	defaultLayout = "templates/layout.html"
	templateDir   = "templates/"

	defaultConfigFile = "config.json"

	githubAuthorizeUrl = "https://github.com/login/oauth/authorize"
	githubTokenUrl     = "https://github.com/login/oauth/access_token"
	redirectUrl        = ""
)

type Config struct {
	ClientSecret string `json:"clientSecret"`
	ClientID     string `json:"clientID"`

	ServerSecret string `json:"serverSecret"`
}

var (
	cfg      *Config
	oauthCfg *oauth2.Config
	store    *sessions.CookieStore

	// scopes
	scopes = []string{"repo"}

	tmpls = map[string]*template.Template{}
)

func loadConfig(file string) (*Config, error) {
	var config Config

	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(b, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func main() {
	tmpls["home.html"] = template.Must(template.ParseFiles(templateDir+"home.html", defaultLayout))

	var err error
	cfg, err = loadConfig(defaultConfigFile)
	if err != nil {
		log.Fatal(err)
	}

	store = sessions.NewCookieStore([]byte(cfg.ServerSecret))

	oauthCfg = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  githubAuthorizeUrl,
			TokenURL: githubTokenUrl,
		},
		RedirectURL: redirectUrl,
		Scopes:      scopes,
	}

	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/start", StartHandler)
	r.HandleFunc("/auth-callback", AuthCallbackHandler)
	r.HandleFunc("/destroy-session", SessionDestroyHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/", r)

	listenAddr := ":8080"

	envPort := os.Getenv("PORT")
	if len(envPort) > 0 {
		listenAddr = ":" + envPort
	}

	log.Printf("attempting listen on %s", listenAddr)
	log.Fatalln(http.ListenAndServe(listenAddr, nil))
}
