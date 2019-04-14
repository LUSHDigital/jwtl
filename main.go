package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"jwtdev/rsautil"
	"jwtdev/tokens"
)

var (
	destination, privatePath, publicPath string
)

func init() {
	const (
		folder  = ".lushdev"
		private = "private_unencrypted.pem"
		public  = "public.pem"
	)

	current, err := user.Current()
	if err != nil {
		log.Fatalf("failed getting current user: %v", err)
	}

	destination = filepath.Join(current.HomeDir, folder)
	privatePath = filepath.Join(destination, private)
	publicPath = filepath.Join(destination, public)

	_, err = os.Stat(destination)
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			if err := os.MkdirAll(filepath.Join(current.HomeDir, folder), os.ModePerm); err != nil {
				log.Fatalln(err)
			}
		}
	}
}

func main() { handleArgs() }

func handleArgs() {
	flag.Parse()
	switch flag.Arg(0) {
	case "generate":
		switch flag.Arg(1) {
		case "keys":
			generateKeys()
		case "jwt":
			var grants []string
			if len(flag.Args()) > 2 {
				grants = flag.Args()[2:]
			}
			generateJwt(grants)
		default:
			log.Fatalln("generate needs a sub-command")
		}
	case "help":
		fallthrough
	default:
		fmt.Printf(`usage:
[generate]:
	[keys]: generates a new rsa key pair under %s
	[jwt]: generates a new jwt, using the generated rsa key pair
`, destination)
	}
}

func generateKeys() {
	private, public, err := rsautil.UnsafelyGenerateKeyPair()
	if err != nil {
		log.Fatalf("failed generating keys: %v", err)
	}
	if err := ioutil.WriteFile(privatePath, private, 0755); err != nil {
		log.Fatalf("failed writing private key: %v", err)
	}
	if err := ioutil.WriteFile(publicPath, public, 0755); err != nil {
		log.Fatalf("failed writing public key: %v", err)
	}
	const keypath = "JWT_PUBLIC_KEY_PATH"
	msg := `Generated keypair:
private: %s
public: %s

Please export this into your environment:

export %s=%s
`
	fmt.Printf(msg, privatePath, publicPath, keypath, publicPath)
}

func generateJwt(grants []string) {
	checkPath := func(path, name string) {
		if _, err := os.Stat(path); err != nil {
			switch err.(type) {
			case *os.PathError:
				log.Fatalf("missing %s, please generate keys first\n", name)
			}
		}
	}

	checkPath(privatePath, "private key")
	checkPath(publicPath, "public key")

	private, err := ioutil.ReadFile(privatePath)
	if err != nil {
		log.Fatalf("failed reading private key: %v", err)
	}
	public, err := ioutil.ReadFile(publicPath)
	if err != nil {
		log.Fatalf("failed reading public key: %v", err)
	}

	token, err := tokens.NewJWT(string(private), string(public), "dev")
	if err != nil {
		log.Fatalf("failed creating jwt: %v", err)
	}
	tok, err := token.GenerateToken(&tokens.Consumer{
		ID:        1,
		FirstName: "dev",
		LastName:  "dev",
		Language:  "en",
		Grants:    grants,
	})
	if err != nil {
		log.Fatalf("failed generating token: %v", err)
	}
	fmt.Println(tok.Value)
}
