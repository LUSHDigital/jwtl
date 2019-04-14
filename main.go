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
		panic(err)
	}

	destination = filepath.Join(current.HomeDir, folder)
	privatePath = filepath.Join(current.HomeDir, folder, private)
	publicPath = filepath.Join(current.HomeDir, folder, public)

	_, err = os.Stat(destination)
	if _, ok := err.(*os.PathError); ok {
		if err := os.MkdirAll(filepath.Join(current.HomeDir, folder), os.ModePerm); err != nil {
			log.Fatal(err)
		}
	}

}
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
		panic(err)
	}
	if err := ioutil.WriteFile(privatePath, private, 0755); err != nil {
		panic(err)
	}
	if err := ioutil.WriteFile(publicPath, public, 0755); err != nil {
		panic(err)
	}
	const keypath = "JWT_PUBLIC_KEY_PATH"
	if err := os.Setenv(keypath, publicPath); err != nil {
		panic(err)
	}
	msg := `Generated keypair:
private: %s
public: %s

Please export this into your environment:

export %s=%s
`
	fmt.Printf(msg, privatePath, publicPath, keypath, publicPath)
}

func generateJwt(grants []string) {
	_, err := os.Stat(privatePath)
	if err != nil {
		log.Fatalln("missing private key, please generate keys first")
	}
	_, err = os.Stat(publicPath)
	if err != nil {
		log.Fatalln("missing public key, please generate keys first")
	}

	private, err := ioutil.ReadFile(privatePath)
	if err != nil {
		panic(err)
	}
	public, err := ioutil.ReadFile(publicPath)
	if err != nil {
		panic(err)
	}

	token, err := tokens.NewJWT(string(private), string(public), "dev")
	if err != nil {
		panic(err)
	}
	tok, err := token.GenerateToken(&tokens.Consumer{
		ID:        1,
		FirstName: "dev",
		LastName:  "dev",
		Language:  "en",
		Grants:    grants,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(tok.Value)
}

func main() {
	handleArgs()
}
