package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"k8s.io/klog"

	"github.com/TianqiuHuang/openID-login/client/pd/auth"
	"github.com/TianqiuHuang/openID-login/client/pkg/templates"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hgfischer/go-otp"
	gtrace "github.com/moxiaomomo/grpc-jaeger"
)

const exampleAppState = "I wish to wash my irish wristwatch"

// App ...
type App struct {
	clientID     string
	clientSecret string
	redirectURI  string
	issuerURL    string

	rawIDToken string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	offlineAsScope bool

	client *http.Client

	port     string
	grpcPort string
	tlsCert  string
	tlsKey   string
}

// New ...
func New(rootCAs, port, grpcPort, issuerURL, redirectURI, clientID, clientSecret, tlsCert, tlsKey string) (*App, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 20 * time.Second,
	}

	if rootCAs != "" {
		tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
		rootCABytes, err := ioutil.ReadFile(rootCAs)
		if err != nil {
			return nil, fmt.Errorf("failed to read root-ca: %v", err)
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
			return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
		}
		tlsConfig.InsecureSkipVerify = true

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tlsConfig,
				Proxy:           http.ProxyFromEnvironment,
				Dial: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).Dial,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}

	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query provider %q: %v", issuerURL, err)
	}

	var offlineAsScope = false

	var s struct {
		// What scopes does a provider support?
		//
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}

	if err := provider.Claims(&s); err != nil {
		return nil, fmt.Errorf("failed to parse provider scopes_supported: %v", err)
	}

	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		offlineAsScope = true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		offlineAsScope = func() bool {
			for _, scope := range s.ScopesSupported {
				if scope == oidc.ScopeOfflineAccess {
					return true
				}
			}
			return false
		}()
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return &App{
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURI:    redirectURI,
		issuerURL:      issuerURL,
		client:         client,
		offlineAsScope: offlineAsScope,
		provider:       provider,
		verifier:       verifier,
		port:           port,
		grpcPort:       grpcPort,
		tlsCert:        tlsCert,
		tlsKey:         tlsKey,
	}, nil
}

// Run ...
func (a *App) Run() error {
	u, err := url.Parse(a.redirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect-uri: %v", err)
	}

	// init tracer
	var servOpts []grpc.ServerOption
	tracer, _, err := gtrace.NewJaegerTracer("authServer", "127.0.0.1:6831")
	if err != nil {
		klog.Fatal("new tracer err: %+v\n", err)
	}
	if tracer != nil {
		servOpts = append(servOpts, gtrace.ServerOption(tracer))
	}

	grpcServer := grpc.NewServer(servOpts...)
	auth.RegisterAuthServiceServer(grpcServer, a)
	lis, err := net.Listen("tcp", ":"+a.grpcPort)
	if err != nil {
		klog.Fatalf("net.Listen err: %v", err)
	}

	go grpcServer.Serve(lis)

	http.HandleFunc("/", a.handleIndex)
	http.HandleFunc("/login", a.handleLogin)
	http.HandleFunc("/passcode", a.handlePassCode)
	http.HandleFunc(u.Path, a.handleCallback)

	if a.tlsCert != "" && a.tlsKey != "" {
		klog.Infof("listen on: 'https://127.0.0.1:%s'", a.port)
		if err := http.ListenAndServeTLS(":"+a.port, a.tlsCert, a.tlsKey, nil); err != nil {
			return err
		}
	} else {
		klog.Infof("listen on: 'http://127.0.0.1:%s'", a.port)
		if err := http.ListenAndServe(":"+a.port, nil); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	templates.RenderIndex(w)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	scopes := []string{"openid", "profile", "email", "groups"}
	authCodeURL := a.oauth2Config(scopes).AuthCodeURL(exampleAppState)
	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (a *App) handlePassCode(w http.ResponseWriter, r *http.Request) {
	passcode := r.FormValue("passcode")
	code, ok := store.Get(passcode)
	if !ok {
		http.Error(w, fmt.Sprintf("passcode not found or expired"), http.StatusNotFound)
		return
	}
	defer store.Delete(passcode)
	var (
		err   error
		token *oauth2.Token
	)
	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)

	token, err = oauth2Config.Exchange(ctx, code.(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		klog.Error("no id_token in token response")
		return
	}

	_, err = a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusInternalServerError)
		klog.Errorf("failed to verify ID token: %v", err)
		return
	}

	var wrapper struct {
		IDToken string `json:"id_token"`
	}

	wrapper.IDToken = rawIDToken
	b, err := json.Marshal(wrapper)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write(b)
}

func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {

	if errMsg := r.FormValue("error"); errMsg != "" {
		http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
		klog.Error(errMsg + ": " + r.FormValue("error_description"))
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
		klog.Errorf("no code in request: %q", r.Form)
		return
	}

	if state := r.FormValue("state"); state != exampleAppState {
		http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
		klog.Errorf("expected state %q got %q", exampleAppState, state)
		return
	}

	token := otp.TOTP{
		Secret:         code,
		IsBase32Secret: true,
	}

	passcode := token.Get()
	if err := store.Add(passcode, code, 5*time.Minute); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	templates.RenderLoginSuccess(w, passcode)
}

func (a *App) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}
}

func (a *App) Validate(ctx context.Context, req *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	idToken, err := a.verifier.Verify(context.Background(), req.GetRawIdToken())
	if err != nil {
		return &auth.ValidateResponse{}, err
	}

	// Extract custom claims.
	var claims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Groups   []string `json:"groups"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return &auth.ValidateResponse{}, err
	}

	return &auth.ValidateResponse{
		Email:  claims.Email,
		Groups: claims.Groups,
	}, nil
}
