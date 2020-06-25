package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type stringSlice []string

func (s stringSlice) Contains(value string) bool {
	for _, x := range s {
		if value == x {
			return true
		}
	}
	return false
}

type intSlice []int

func (s intSlice) Contains(value int) bool {
	for _, x := range s {
		if value == x {
			return true
		}
	}
	return false
}

func stringSliceToIntSlice(strs []string) (intSlice, error) {
	ints := intSlice(make([]int, 0, len(strs)))
	for _, s := range strs {
		i, err := strconv.Atoi(s)
		if err != nil {
			return ints, err
		}
		ints = append(ints, i)
	}
	return ints, nil
}

type errInvalidScheme struct {
	Scheme string
}

func (e *errInvalidScheme) Error() string {
	return "invalid scheme " + e.Scheme + ", only http and https are supported"
}

type errInvalidPath struct {
	Path string
}

func (e *errInvalidPath) Error() string {
	return "invalid path " + e.Path
}

type errInvalidStatusCode struct {
	Code int
}

func (e *errInvalidStatusCode) Error() string {
	return "invalid status code " + strconv.Itoa(e.Code)
}

type errHealthCheck struct {
	URL        string
	StatusCode int
	Tries      int
}

func (e *errHealthCheck) Error() string {
	return "request to url " + e.URL + " returned invalid status code " + strconv.Itoa(e.StatusCode) + " after " + strconv.Itoa(e.Tries) + " tries"
}

// version is the published version of the utility
var version string

const (
	// SchemesFlag is the Schemes Flag
	SchemesFlag string = "schemes"
	// HostsFlag is the Hosts Flag
	HostsFlag string = "hosts"
	// PathsFlag is the Paths Flag
	PathsFlag string = "paths"
	// KeyFlag is the Key Flag
	KeyFlag string = "key"
	// KeyFileFlag is the Key File Flag
	KeyFileFlag string = "key-file"
	// CertFlag is the Cert Flag
	CertFlag string = "cert"
	// CertFileFlag is the Cert File Flag
	CertFileFlag string = "cert-file"
	// CAFlag is the CA Flag
	CAFlag string = "ca"
	// CAFileFlag is the CA File Flag
	CAFileFlag string = "ca-file"
	// StatusCodesFlag is the Status Codes Flag
	StatusCodesFlag string = "status-codes"
	// SkipVerifyFlag is the Skip Verify Flag
	SkipVerifyFlag string = "skip-verify"
	// TriesFlag is the Tries Flag
	TriesFlag string = "tries"
	// BackoffFlag is the Backoff Flag
	BackoffFlag string = "backoff"
	// TimeoutFlag is the Timeout Flag
	TimeoutFlag string = "timeout"
	// ExitOnErrorFlag is the ExitOnError Flag
	ExitOnErrorFlag string = "exit-on-error"
	// LogEnvFlag is the LogEnv Flag
	LogEnvFlag string = "log-env"
	// LogLevelFlag is the LogLevel Flag
	LogLevelFlag string = "log-level"
	// VerboseFlag is the Verbose Flag
	VerboseFlag string = "verbose"
)

func initFlags(flag *pflag.FlagSet) {

	// Health URLs
	flag.StringP(SchemesFlag, "s", "http,https", "slice of schemes to check")
	flag.String(HostsFlag, "", "comma-separated list of host names to check")
	flag.StringP(PathsFlag, "p", "/health", "slice of paths to check on each host")

	// Mutual TLS
	flag.String(KeyFlag, "", "path to file of base64-encoded private key for client TLS")
	flag.String(KeyFileFlag, "", "path to file of base64-encoded private key for client TLS")
	flag.String(CertFlag, "", "base64-encoded public key for client TLS")
	flag.String(CertFileFlag, "", "path to file of base64-encoded public key for client TLS")
	flag.String(CAFlag, "", "base64-encoded certificate authority for mutual TLS")
	flag.String(CAFileFlag, "", "path to file of base64-encoded certificate authority for mutual TLS")
	flag.String(StatusCodesFlag, "200", "valid response status codes")
	flag.Bool(SkipVerifyFlag, false, "skip certifiate validation")

	// Retry
	flag.Int(TriesFlag, 5, "number of tries")
	flag.Int(BackoffFlag, 1, "backoff in seconds")
	flag.Duration(TimeoutFlag, 5*time.Minute, "timeout duration")

	// Exit
	flag.Bool(ExitOnErrorFlag, false, "exit on first health check error")

	// Logging
	flag.String(LogEnvFlag, "development", "logging config: development or production")
	flag.String(LogLevelFlag, "error", "log level: debug, info, warn, error, dpanic, panic, or fatal")

	// Verbose
	flag.BoolP(VerboseFlag, "v", false, "log messages at the debug level.")

	flag.SortFlags = false
}

func checkConfig(v *viper.Viper) error {
	schemesString := strings.TrimSpace(v.GetString("schemes"))

	if len(schemesString) == 0 {
		return errors.New("missing schemes")
	}

	schemes := stringSlice(strings.Split(schemesString, ","))

	for _, scheme := range schemes {
		if scheme != "http" && scheme != "https" {
			return &errInvalidScheme{Scheme: scheme}
		}
	}

	hosts := v.GetString(HostsFlag)

	if len(hosts) == 0 {
		return errors.New("missing hosts")
	}

	pathsString := v.GetString(PathsFlag)

	if len(pathsString) == 0 {
		return errors.New("missing paths")
	}

	paths := stringSlice(strings.Split(pathsString, ","))

	for _, path := range paths {
		if !strings.HasPrefix(path, "/") {
			return &errInvalidPath{Path: path}
		}
	}

	statusCodesString := strings.TrimSpace(v.GetString(StatusCodesFlag))
	if len(statusCodesString) == 0 {
		return errors.New("missing status codes")
	}

	statusCodes, err := stringSliceToIntSlice(strings.Split(statusCodesString, ","))
	if err != nil {
		return errors.Wrap(err, "invalid status codes")
	}

	for _, statusCode := range statusCodes {
		if len(http.StatusText(statusCode)) == 0 {
			return &errInvalidStatusCode{Code: statusCode}
		}
	}

	clientKeyEncoded := v.GetString(KeyFlag)
	clientCertEncoded := v.GetString(CertFlag)
	clientKeyFile := v.GetString(KeyFileFlag)
	clientCertFile := v.GetString(CertFileFlag)

	if len(clientKeyEncoded) > 0 || len(clientCertEncoded) > 0 || len(clientKeyFile) > 0 || len(clientCertFile) > 0 {
		if schemes.Contains("http") {
			return errors.New("cannot use scheme http with client certificate, can only use https")
		}
	}

	tries := v.GetInt(TriesFlag)
	if tries == 0 {
		return errors.New("tries is 0, but must be greater than zero")
	}

	if tries > 1 {
		backoff := v.GetInt(BackoffFlag)
		if backoff == 0 {
			return errors.New("backoff is 0, but must be greater than zero")
		}
	}

	return nil
}

func createTLSConfig(clientKey []byte, clientCert []byte, ca []byte, insecureSkipVerify bool) (*tls.Config, error) {

	keyPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	// #nosec b/c gosec triggers on InsecureSkipVerify
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{keyPair},
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	if len(ca) > 0 {
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = rootCAs
	}

	return tlsConfig, nil
}

func createHTTPClient(v *viper.Viper, logger *zap.Logger) (*http.Client, error) {

	verbose := v.GetBool(VerboseFlag)

	clientKeyEncoded := v.GetString(KeyFlag)
	clientCertEncoded := v.GetString(CertFlag)
	skipVerify := v.GetBool(SkipVerifyFlag)
	timeout := v.GetDuration(TimeoutFlag)

	if verbose {
		if skipVerify {
			logger.Info("Skipping client-side certificate validation")
		}
	}

	// Supported TLS versions
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	if len(clientKeyEncoded) > 0 && len(clientCertEncoded) > 0 {

		clientKey, clientKeyErr := base64.StdEncoding.DecodeString(clientKeyEncoded)
		if clientKeyErr != nil {
			return nil, errors.Wrap(clientKeyErr, "error decoding client key")
		}

		clientCert, clientCertErr := base64.StdEncoding.DecodeString(clientCertEncoded)
		if clientCertErr != nil {
			return nil, errors.Wrap(clientCertErr, "error decoding client cert")
		}

		caBytes := make([]byte, 0)
		if caEncoded := v.GetString(CAFlag); len(caEncoded) > 0 {
			caString, err := base64.StdEncoding.DecodeString(caEncoded)
			if err != nil {
				return nil, errors.Wrap(err, "error decoding certificate authority")
			}
			caBytes = []byte(caString)
		}

		var tlsConfigErr error
		tlsConfig, tlsConfigErr = createTLSConfig([]byte(clientKey), []byte(clientCert), caBytes, false)
		if tlsConfigErr != nil {
			return nil, errors.Wrap(tlsConfigErr, "error creating TLS config")
		}

	} else {

		clientKeyFile := v.GetString(KeyFileFlag)
		clientCertFile := v.GetString(CertFileFlag)

		if len(clientKeyFile) > 0 && len(clientCertFile) > 0 {

			clientKey, clientKeyErr := ioutil.ReadFile(clientKeyFile) // #nosec b/c we need to read a file from a user-defined path
			if clientKeyErr != nil {
				return nil, errors.Wrap(clientKeyErr, "error reading client key file at "+clientKeyFile)
			}

			clientCert, clientCertErr := ioutil.ReadFile(clientCertFile) // #nosec b/c we need to read a file from a user-defined path
			if clientCertErr != nil {
				return nil, errors.Wrap(clientCertErr, "error reading client cert file at "+clientKeyFile)
			}

			caBytes := make([]byte, 0)
			if caFile := v.GetString(CAFileFlag); len(caFile) > 0 {
				content, err := ioutil.ReadFile(caFile) // #nosec b/c we need to read a file from a user-defined path
				if err != nil {
					return nil, errors.Wrap(err, "error reading ca file at "+caFile)
				}
				caBytes = content
			}
			var tlsConfigErr error
			tlsConfig, tlsConfigErr = createTLSConfig(clientKey, clientCert, caBytes, false)
			if tlsConfigErr != nil {
				return nil, errors.Wrap(tlsConfigErr, "error creating TLS config")
			}
		}
	}

	httpTransport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}
	return httpClient, nil

}

func checkURL(httpClient *http.Client, url string, validStatusCodes intSlice, maxTries int, backoff int, logger *zap.Logger) error {
	for tries := 0; tries < maxTries; tries++ {
		statusCode := 0
		resp, err := httpClient.Get(url)
		if err != nil {
			if uerr, ok := err.(*neturl.Error); ok && uerr.Timeout() {
				logger.Info(
					"HTTP GET request timed out",
					zap.Int("try", tries),
					zap.String("url", url))
			} else {
				return errors.Wrap(err, "error calling GET on url "+url)
			}
		} else {
			statusCode = resp.StatusCode
			logger.Info(
				"HTTP GET request completed",
				zap.Int("try", tries),
				zap.String("url", url),
				zap.Int("code", statusCode))
			if validStatusCodes.Contains(statusCode) {
				break
			}
		}
		if tries < maxTries-1 {
			sleepPeriod := time.Duration((tries+1)*backoff) * time.Second
			logger.Info("sleeping", zap.Duration("period", sleepPeriod))
			time.Sleep(sleepPeriod)
			continue
		}
		return &errHealthCheck{URL: url, StatusCode: statusCode, Tries: maxTries}
	}
	return nil
}

func createLogger(env string, level string) (*zap.Logger, error) {
	loglevel := zapcore.Level(uint8(0))
	err := (&loglevel).UnmarshalText([]byte(level))
	if err != nil {
		return nil, err
	}
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(loglevel)
	var loggerConfig zap.Config
	if env == "production" || env == "prod" {
		loggerConfig = zap.NewProductionConfig()
	} else {
		loggerConfig = zap.NewDevelopmentConfig()
	}
	loggerConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	loggerConfig.Level = atomicLevel
	loggerConfig.DisableStacktrace = true
	return loggerConfig.Build(zap.AddStacktrace(zap.ErrorLevel))
}

func main() {
	root := cobra.Command{
		Use:   "health-checker [flags]",
		Short: "Website Health Check",
		Long:  "Website Health Check",
	}

	completionCommand := &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long:  "To install completion scripts run:\nhealth-checker completion > /usr/local/etc/bash_completion.d/health-checker",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(os.Stdout)
		},
	}
	root.AddCommand(completionCommand)

	healthCheckerCheckCommand := &cobra.Command{
		Use:                   "check [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Website Health Check",
		Long:                  "Website Health Check",
		RunE:                  healthCheckerCheckFunction,
	}
	initFlags(healthCheckerCheckCommand.Flags())
	root.AddCommand(healthCheckerCheckCommand)

	healthCheckerVersionCommand := &cobra.Command{
		Use:                   "version",
		DisableFlagsInUseLine: true,
		Short:                 "Print the version",
		Long:                  "Print the version",
		RunE:                  healthCheckerVersionFunction,
	}
	root.AddCommand(healthCheckerVersionCommand)

	if err := root.Execute(); err != nil {
		panic(err)
	}
}

func healthCheckerVersionFunction(cmd *cobra.Command, args []string) error {
	if len(version) == 0 {
		fmt.Println("development")
		return nil
	}
	fmt.Println(version)
	return nil
}

func healthCheckerCheckFunction(cmd *cobra.Command, args []string) error {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()

	err := cmd.ParseFlags(args)
	if err != nil {
		return err
	}

	flag := cmd.Flags()

	v := viper.New()
	bindErr := v.BindPFlags(flag)
	if bindErr != nil {
		return bindErr
	}
	v.SetEnvPrefix("HEALTHCHECKER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	healthCheckErrors := make([]error, 0)
	defer func() {
		if len(healthCheckErrors) > 0 {
			os.Exit(1)
		}
	}()

	logger, err := createLogger(v.GetString(LogEnvFlag), v.GetString(LogLevelFlag))
	if err != nil {
		log.Fatal(err.Error())
	}

	defer func() {
		_ = logger.Sync()
	}()

	err = checkConfig(v)
	if err != nil {
		switch e := err.(type) {
		case *errInvalidPath:
			logger.Fatal(e.Error(), zap.String("path", e.Path))
		case *errInvalidScheme:
			logger.Fatal(e.Error(), zap.String("scheme", e.Scheme))
		case *errInvalidStatusCode:
			logger.Fatal(e.Error(), zap.Int("code", e.Code))
		}
		logger.Fatal(err.Error())
	}

	verbose := v.GetBool(VerboseFlag)
	schemes := strings.Split(strings.TrimSpace(v.GetString(SchemesFlag)), ",")
	hosts := strings.Split(strings.TrimSpace(v.GetString(HostsFlag)), ",")
	paths := strings.Split(strings.TrimSpace(v.GetString(PathsFlag)), ",")
	statusCodes, _ := stringSliceToIntSlice(strings.Split(strings.TrimSpace(v.GetString(StatusCodesFlag)), ","))

	httpClient, err := createHTTPClient(v, logger)
	if err != nil {
		logger.Fatal(errors.Wrap(err, "error creating http client").Error())
	}

	maxTries := v.GetInt(TriesFlag)
	backoff := v.GetInt(BackoffFlag)
	exitOnError := v.GetBool(ExitOnErrorFlag)

	for _, scheme := range schemes {
		for _, host := range hosts {
			for _, path := range paths {
				url := scheme + "://" + host + path
				if verbose {
					logger.Info("checking url will connect", zap.String("url", url))
				}
				err := checkURL(httpClient, url, statusCodes, maxTries, backoff, logger)
				if err != nil {
					if exitOnError {
						switch e := err.(type) {
						case *errHealthCheck:
							logger.Fatal(
								"health check failed",
								zap.String("url", e.URL),
								zap.Int("statusCode", e.StatusCode),
								zap.Int("tries", e.Tries))
						default:
							logger.Fatal(err.Error())
						}
					} else {
						switch e := err.(type) {
						case *errHealthCheck:
							logger.Warn(
								"health check failed",
								zap.String("url", e.URL),
								zap.Int("statusCode", e.StatusCode),
								zap.Int("tries", e.Tries))
						default:
							logger.Warn(err.Error())
						}
						healthCheckErrors = append(healthCheckErrors, err)
					}
				}
			}
		}
	}
	return nil
}
