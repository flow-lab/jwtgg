package main

import (
	"bytes"
	"encoding/json"
	"github.com/flow-lab/dlog"
	utils "github.com/flow-lab/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is the configuration for the client
type Config struct {
	// Audience is the url, e.g. https://test.maskinporten.no
	Audience string
	// Endpoint is the url to the token endpoint, e.g. https://test.maskinporten.no/token
	Endpoint string
	// Issuer is the client id of the client
	Issuer string
	// Scopes is the scopes the client is requesting
	Scopes string
	// KID is the key id of the public key used to verify the JWT
	KID string
	// PrivateKey is the path to the private key used to sign the JWT
	PrivateKey string
	// Resource is the resource the client is requesting
	Resource string
}

// Token is the response from the token endpoint
type Token struct {
	// AccessToken is the access token
	AccessToken string `json:"access_token"`
	// TokenType is the type of token, e.g. Bearer
	TokenType string `json:"token_type"`
	// ExpiresIn is the number of seconds the token is valid
	ExpiresIn int64 `json:"expires_in"`
	// Scope is the scopes granted to the client
	Scope string `json:"scope"`
}

func loadConfig() Config {
	// source .env file
	f, err := os.ReadFile(".env")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(f), "\n")
	for _, v := range lines {
		if v == "" {
			continue
		}
		keyVal := strings.Split(v, "=")
		err := os.Setenv(keyVal[0], keyVal[1])
		if err != nil {
			panic(err)
		}
	}

	return Config{
		Audience:   utils.MustGetEnv("AUD"),
		Endpoint:   utils.MustGetEnv("ENDPOINT"),
		Issuer:     utils.MustGetEnv("ISS"),
		Scopes:     utils.EnvOrDefault("SCOPES", ""),
		Resource:   utils.EnvOrDefault("RESOURCE", ""),
		KID:        utils.MustGetEnv("KID"),
		PrivateKey: utils.MustGetEnv("PRIVATE_KEY"),
	}
}

func main() {
	logger := dlog.NewLogger(&dlog.Config{
		AppName:      "jwtgg",
		Level:        "debug",
		Version:      "0.1.0",
		ReportCaller: true,
		Formatter:    "text",
	})

	// catch and log panics and propagate them
	defer func() {
		if r := recover(); r != nil {
			logger.Fatalf("panic: %s", r)
		}
	}()

	config := loadConfig()
	jwtToken, err := generateJWT(&config)
	if err != nil {
		logger.Fatalf("failed to generate JWT: %s", err)
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", jwtToken) // Set the JWT here

	resp, err := http.PostForm(config.Endpoint, data)
	if err != nil {
		logger.Fatalf("failed to get token: %s", err)
	}
	defer resp.Body.Close()

	// print body as string
	tokenResp, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Fatalf("failed to read response body: %s", err)
	}

	if resp.StatusCode != 200 {
		logger.Fatalf("failed to get token: %s. Response status: %s", string(tokenResp), resp.Status)
	}

	logger.Debugf("token from maskinporten: %s", string(tokenResp))

	if len(os.Args) < 2 || os.Args[1] != "-svv" {
		return
	}
	logger.Debugf("svv flag set, getting vehicle data including owner information")

	token := Token{}
	if err := json.Unmarshal(tokenResp, &token); err != nil {
		logger.Fatalf("failed to unmarshal token: %s", err)
	}

	// test request
	// API - Tekniske Kjøretøyopplysninger med Eierinformasjon
	// https://autosys-kjoretoy-api.atlas.vegvesen.no/api-ui/index-tekniske-kjoretoyopplysninger-med-eierinformasjon.html

	// Kjoretoyopplysninger is the request body
	type Kjoretoyopplysninger struct {
		// Kjennemerke is the registration number
		Kjennemerke string `json:"kjennemerke"`
		// AtDateTime, dtg (dato-tidsgruppe) hvis klienten ønsker informasjon på et gitt tidspunkt.
		AtDateTime string `json:"dtg"`
	}

	// test data from https://autosys-kjoretoy-api.atlas.vegvesen.no/kodeverk-ui/index-testdata-sisdinky.html
	// CU11306, CU11293
	var reqBody []Kjoretoyopplysninger
	for _, regNr := range []string{"CU11306", "CU11293"} {
		reqBody = append(reqBody, Kjoretoyopplysninger{
			Kjennemerke: regNr,
			AtDateTime:  time.Now().Format(time.RFC3339),
		})
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		logger.Fatalf("failed to marshal request body: %s", err)
	}

	req := http.Request{
		Header: map[string][]string{
			"Authorization": {token.TokenType + " " + token.AccessToken},
			"Content-Type":  {"application/json"},
		},
		Method: http.MethodPost,
		Body:   io.NopCloser(bytes.NewReader(body)),
		URL:    &url.URL{Scheme: "https", Host: "akfell-datautlevering-sisdinky.utv.atlas.vegvesen.no", Path: "/kjoretoyoppslag/bulk/kjennemerke"},
	}

	client := http.Client{}
	res, err := client.Do(&req)
	if err != nil {
		logger.Fatalf("failed to call /kjoretoyoppslag/bulk/kjennemerke: %s", err)
	}

	logger.Debugf("response status: %s", res.Status)
	outFileName := "response.json"
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Fatalf("failed to read response body: %s", err)
	}
	if err := os.WriteFile(outFileName, resBody, 0644); err != nil {
		logger.Fatalf("failed to write response to file: %s", err)
	}
	logger.Infof("response written to file: %s", outFileName)
}

func generateJWT(c *Config) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)

	token.Header["alg"] = "RS256"
	token.Header["kid"] = c.KID

	claims := token.Claims.(jwt.MapClaims)
	now := time.Now().UTC()
	claims["aud"] = c.Audience
	claims["iss"] = c.Issuer
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Second * 12).Unix()
	claims["jti"] = uuid.New().String()
	if c.Scopes != "" {
		claims["scope"] = c.Scopes
	}
	if c.Resource != "" {
		claims["resource"] = c.Resource
	}

	key, err := openFile(c.PrivateKey)
	if err != nil {
		return "", err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key))
	if err != nil {
		return "", err
	}

	jwtToken, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}

func openFile(path string) (string, error) {
	// open file and return the key
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
