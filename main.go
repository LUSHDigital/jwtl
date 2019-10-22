package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/LUSHDigital/core/auth"
	"github.com/LUSHDigital/jwtl/unsafersa"
)

var (
	privatePath    string
	publicPath     string
	jwtKeysPath    string
	jwtKeysName    string
	jwtValidFrom   string
	jwtValidPeriod = "60m"

	now           func() time.Time
	validDuration time.Duration

	userID        = int64(1)
	userUUID      = "67e89fbc-41eb-4090-b67b-f22b80ced238"
	userFirstName = "John"
	userLastName  = "Doe"
	userRoles     = "guest"
	userGrants    = "read,write"
	userNeeds     = "nothing"
	lang          = "en"
)

const (
	// IssuerName represents the name of the JWT issuer.
	IssuerName = "Developer Command Line"

	// ReadOnly file mode for key pairs.
	ReadOnly = 0755

	// JWTKeysPathEnv represents the path of a key pair.
	JWTKeysPathEnv = "JWT_KEYS_PATH"

	// JWTKeysNameEnv represents the name of the a key pair in the keys path.
	JWTKeysNameEnv = "JWT_KEYS_NAME"

	// JWTPublicKeyEnv represents the environment variable for the JWT public key as in the LUSHDigital/core library.
	JWTPublicKeyEnv = "JWT_PUBLIC_KEY_PATH"

	// JWTPrivateKeyEnv represents the environment variable for the JWT private key as in the LUSHDigital/core library.
	JWTPrivateKeyEnv = "JWT_PRIVATE_KEY_PATH"

	// JWTValidPeriodEnv represents the environment variable for the duration the JWT token is valid for.
	JWTValidPeriodEnv = "JWT_VALID_PERIOD"

	// JWTValidFrom represents an environment variable for what timestamp to use for the current time.
	JWTValidFrom = "JWT_VALID_FROM"

	// PrivateKeySuffix is the name suffix for a private key for a given key pair name.
	PrivateKeySuffix = "private_unencrypted"

	// PublicKeySuffix is the name suffix for a public key for a given key pair name.
	PublicKeySuffix = "public"

	// DefaultName is the key pair name we we use if no configuration is provided.
	DefaultName = "jwt"
)

func main() {
	current, err := user.Current()
	if err != nil {
		log.Fatalf("failed getting current user: %v", err)
	}

	// Derive the jwt keys path from the environment if possible.
	jwtKeysPath = os.Getenv(JWTKeysPathEnv)
	if jwtKeysPath == "" {
		jwtKeysPath = filepath.Join(current.HomeDir)
	}

	// Derive the jwt keys name from the environment if possible.
	jwtKeysName = os.Getenv(JWTKeysNameEnv)
	if jwtKeysName == "" {
		jwtKeysName = DefaultName
	}

	// Derive the jwt validity duration from the environment if possible.
	if s := os.Getenv(JWTValidPeriodEnv); s != "" {
		jwtValidPeriod = s
	}

	jwtValidFrom = time.Now().Format(time.RFC3339)
	if s := os.Getenv(JWTValidFrom); s != "" {
		jwtValidFrom = s
	}

	flag.StringVar(&jwtKeysPath, "path", jwtKeysPath, "Path on disk to the location to use or generate the keys")
	flag.StringVar(&jwtKeysName, "name", jwtKeysName, "Name of the keys to use or generate in the location")
	flag.StringVar(&jwtValidPeriod, "valid_period", jwtValidPeriod, "Duration the generated keys are valid")
	flag.StringVar(&jwtValidFrom, "valid_from", jwtValidFrom, "Timestamp used to determine the time when a token is valid")
	flag.Int64Var(&userID, "uid", userID, "ID of the consumer")
	flag.StringVar(&userUUID, "uuid", userUUID, "UUID of the consumer")
	flag.StringVar(&userFirstName, "firstname", userFirstName, "First name of the consumer")
	flag.StringVar(&userLastName, "lastname", userLastName, "Last name of the consumer")
	flag.StringVar(&userGrants, "grants", userGrants, "Grants of the consumer as a comma separated list")
	flag.StringVar(&userRoles, "roles", userRoles, "Roles of the consumer as a comma separated list")
	flag.StringVar(&userNeeds, "needs", userNeeds, "Needs of the consumer as a comma separated list")

	flag.StringVar(&lang, "lang", lang, "Language of the consumer")

	flag.Parse()

	d, err := time.ParseDuration(jwtValidPeriod)
	if err != nil {
		log.Fatalf("cannot parse token valid period duration: %v", err)
	}
	validDuration = d

	t, err := time.Parse(time.RFC3339, jwtValidFrom)
	if err != nil {
		log.Fatalf("cannot parse token valid from timestamp: %v", err)
	}
	now = func() time.Time { return t }

	mkdir(jwtKeysPath)

	const tmpl = "%s.%s.pem"
	privatePath = filepath.Join(jwtKeysPath, fmt.Sprintf(tmpl, jwtKeysName, PrivateKeySuffix))
	publicPath = filepath.Join(jwtKeysPath, fmt.Sprintf(tmpl, jwtKeysName, PublicKeySuffix))

	grants := strings.Split(userGrants, ",")
	roles := strings.Split(userRoles, ",")
	needs := strings.Split(userNeeds, ",")

	switch flag.Arg(0) {
	case "setup":
		setup()
	case "new":
		config := auth.IssuerConfig{
			Name:        IssuerName,
			ValidPeriod: validDuration,
			TimeFunc:    time.Now,
		}
		consumer := &auth.Consumer{
			ID:        userID,
			UUID:      userUUID,
			FirstName: "John",
			LastName:  "Doe",
			Language:  "en",
			Grants:    grants,
			Roles:     roles,
			Needs:     needs,
		}
		generate(config, consumer)
	case "help":
		fallthrough
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "   %s new\n\tGenerates a JWT token based on an RSA key pair\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "   %s setup\n\tGenerates a new RSA key pair\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
	flag.PrintDefaults()
}

const exportMessage = `Please export this into your environment to reuse the configuration:

export %s=%s
export %s=%s
export %s=%s
export %s=%s
export %s=%s

`

func setup() {
	private, public, err := unsafersa.GenerateUnsafeKeyPair()
	if err != nil {
		log.Fatalf("failed generating keys: %v", err)
	}
	if err := ioutil.WriteFile(privatePath, private, ReadOnly); err != nil {
		log.Fatalf("failed writing private key: %v", err)
	}
	if err := ioutil.WriteFile(publicPath, public, ReadOnly); err != nil {
		log.Fatalf("failed writing public key: %v", err)
	}

	fmt.Printf("Generated key pair\n  %s\n  %s\n\n", privatePath, publicPath)
	fmt.Printf(exportMessage,
		JWTKeysPathEnv, jwtKeysPath,
		JWTKeysNameEnv, jwtKeysName,
		JWTPublicKeyEnv, publicPath,
		JWTPrivateKeyEnv, privatePath,
		JWTValidPeriodEnv, validDuration.String(),
	)
}

func generate(config auth.IssuerConfig, consumer *auth.Consumer) {
	check(privatePath)
	private, err := ioutil.ReadFile(privatePath)
	if err != nil {
		log.Fatalf("failed reading private key: %v", err)
	}
	issuer, err := auth.NewIssuerFromPrivateKeyPEM(config, private)
	if err != nil {
		log.Fatalf("cannot create token issuer: %v", err)
	}
	token, err := issuer.Issue(consumer)
	if err != nil {
		log.Fatalf("cannot issue token: %v", err)
	}
	fmt.Println(token)
}

func mkdir(path string) {
	_, err := os.Stat(path)
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			if err := os.MkdirAll(path, os.ModePerm); err != nil {
				log.Fatalln(err)
			}
		}
	}
}

func check(path string) {
	if _, err := os.Stat(path); err != nil {
		switch err.(type) {
		case *os.PathError:
			log.Fatalf("missing %s, please generate keys first\n", path)
		}
	}
}
