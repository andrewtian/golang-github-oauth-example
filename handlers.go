package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/google/go-github/github"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

const sessionStoreKey = "sess"

func init() {
	gob.Register(&oauth2.Token{})
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionStoreKey)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	renderData := map[string]interface{}{}
	if accessToken, ok := session.Values["githubAccessToken"].(*oauth2.Token); ok {
		client := github.NewClient(oauthCfg.Client(oauth2.NoContext, accessToken))

		user, _, err := client.Users.Get(context.Background(), "")
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		renderData["github_user"] = user

		var userMap map[string]interface{}
		mapstructure.Decode(user, &userMap)
		renderData["github_user_map"] = userMap
	}

	tmpls["home.html"].ExecuteTemplate(w, "base", renderData)
}

func StartHandler(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	rand.Read(b)

	state := base64.URLEncoding.EncodeToString(b)

	session, _ := store.Get(r, sessionStoreKey)
	session.Values["state"] = state
	session.Save(r, w)

	url := oauthCfg.AuthCodeURL(state)
	http.Redirect(w, r, url, 302)
}

func AuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionStoreKey)
	if err != nil {
		fmt.Fprintln(w, "aborted")
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		fmt.Fprintln(w, "no state match; possible csrf OR cookies not enabled")
		return
	}

	token, err := oauthCfg.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
	if err != nil {
		fmt.Fprintln(w, "there was an issue getting your token")
		return
	}

	if !token.Valid() {
		fmt.Fprintln(w, "retreived invalid token")
		return
	}

	client := github.NewClient(oauthCfg.Client(oauth2.NoContext, token))

	user, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		fmt.Println(w, "error getting name")
		return
	}

	session.Values["githubUserName"] = user.Name
	session.Values["githubAccessToken"] = token
	session.Save(r, w)

	http.Redirect(w, r, "/", 302)
}

// http://www.gorillatoolkit.org/pkg/sessions#CookieStore.MaxAge
func SessionDestroyHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionStoreKey)
	if err != nil {
		fmt.Fprintln(w, "aborted")
		return
	}

	session.Options.MaxAge = -1

	session.Save(r, w)
	http.Redirect(w, r, "/", 302)

}

// func sessionGithubUser(r *http.Request) error {
// 	session, err := store.Get(r, "sess")
// 	if err != nil {
// 		return err
// 	}

// 	accessToken, ok := session.Values["githubAccessToken"].(*oauth2.Token); ok {
// 		client := github.NewClient(oauthCfg.Client(oauth2.NoContext, accessToken))

// 	}

// 	return nil
// }
