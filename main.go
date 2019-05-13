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

	"github.com/LUSHDigital/core/auth"

	"jwtdev/unsafersa"
)

var (
	privatePath string
	publicPath  string
	jwtKeysPath string
	jwtKeysName string

	userID        = int64(1)
	userFirstName = "John"
	userLastName  = "Doe"
	lang          = "en"

	userRoles  = "guest"
	userGrants = "read,write"
)

const (
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

	flag.StringVar(&jwtKeysPath, "path", jwtKeysPath, "Path on disk to the location to use or generate the keys")
	flag.StringVar(&jwtKeysName, "name", jwtKeysName, "Name of the keys to use or generate in the location")

	flag.Int64Var(&userID, "uid", userID, "ID of the consumer")
	flag.StringVar(&userFirstName, "firstname", userFirstName, "First name of the consumer")
	flag.StringVar(&userLastName, "lastname", userLastName, "Last name of the consumer")
	flag.StringVar(&lang, "lang", lang, "Language of the consumer")

	flag.StringVar(&userGrants, "grants", userGrants, "Grants of the consumer as a comma separated list")
	flag.StringVar(&userRoles, "roles", userRoles, "Roles of the consumer as a comma separated list")

	flag.Parse()

	mkdir(jwtKeysPath)

	const tmpl = "%s.%s.pem"
	privatePath = filepath.Join(jwtKeysPath, fmt.Sprintf(tmpl, jwtKeysName, PrivateKeySuffix))
	publicPath = filepath.Join(jwtKeysPath, fmt.Sprintf(tmpl, jwtKeysName, PublicKeySuffix))

	grants := strings.Split(userGrants, ",")
	roles := strings.Split(userRoles, ",")

	switch flag.Arg(0) {
	case "setup":
		setup()
	case "new":
		consumer := &auth.Consumer{
			ID:        1,
			FirstName: "John",
			LastName:  "Doe",
			Language:  "en",
			Grants:    grants,
			Roles:     roles,
		}
		generate(consumer)
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
	const exportMessage = `Please export this into your environment to reuse the configuration:

export %s=%s
export %s=%s
export %s=%s
export %s=%s

`
	fmt.Printf(exportMessage, JWTKeysPathEnv, jwtKeysPath, JWTKeysNameEnv, jwtKeysName, JWTPublicKeyEnv, publicPath, JWTPrivateKeyEnv, privatePath)
}

func generate(consumer *auth.Consumer) {
	check(privatePath)
	private, err := ioutil.ReadFile(privatePath)
	if err != nil {
		log.Fatalf("failed reading private key: %v", err)
	}
	cfg := auth.IssuerConfig{
		Name: "Developer Command Line",
	}
	issuer, err := auth.NewIssuerFromPrivateKeyPEM(cfg, private)
	if err != nil {
		log.Fatalf("cannot create token issuer: %v", err)
	}
	token, err := issuer.Issue(consumer)
	if err != nil {
		log.Fatalf("cannot create token issuer: %v", err)
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
