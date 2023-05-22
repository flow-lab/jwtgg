package main

import (
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Fatalf("failed to read response body: %s", err)
	}

	if resp.StatusCode != 200 {
		logger.Fatalf("failed to get token: %s. Response status: %s", string(b), resp.Status)
	}

	logger.Debugf("access token: %s", string(b))
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
