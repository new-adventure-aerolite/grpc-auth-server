package cmd

import (
	"github.com/TianqiuHuang/openID-login/client/pkg/app"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

var (
	rootCAs      string
	port         string
	grpcPort     string
	issuerURL    string
	redirectURI  string
	clientID     string
	clientSecret string
	tlsCert      string
	tlsKey       string
)

var rootCmd = cobra.Command{
	Use:   "openid",
	Short: "client side to login with openID",
	Run: func(cmd *cobra.Command, args []string) {
		app, err := app.New(rootCAs, port, grpcPort, issuerURL, redirectURI, clientID, clientSecret, tlsCert, tlsKey)
		if err != nil {
			klog.Fatal(err)
		}
		if err = app.Run(); err != nil {
			klog.Fatal(err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVar(&clientID, "client-id", "example-app", "OAuth2 client ID of this application.")
	rootCmd.Flags().StringVar(&clientSecret, "client-secret", "ZXhhbXBsZS1hcHAtc2VjcmV0", "OAuth2 client secret of this application.")
	rootCmd.Flags().StringVar(&redirectURI, "redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	rootCmd.Flags().StringVar(&issuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	rootCmd.Flags().StringVar(&port, "port", "5555", "listen port")
	rootCmd.Flags().StringVar(&grpcPort, "grpc-port", "6666", "listen grpc port")
	rootCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "X509 cert file to present when serving HTTPS.")
	rootCmd.Flags().StringVar(&tlsKey, "tls-key", "", "Private key for the HTTPS cert.")
	rootCmd.Flags().StringVar(&rootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
}

// Execute ...
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}
