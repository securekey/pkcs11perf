/*
   Copyright SecureKey Technologies Inc.
   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without written permission from SecureKey.
*/
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/pkg/errors"
	"github.com/securekey/pkcs11perf/pkcss11/wrapper"
	"github.com/spf13/cobra"
)

const (
	hsmLibs = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/softhsm/libsofthsm2.so,/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so, /usr/local/Cellar/softhsm/2.5.0/lib/softhsm/libsofthsm2.so"
)

var (
	hashAlgorithm  string // SHA2
	level          int    // 256
	library        string // "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/softhsm/libsofthsm2.so,/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so, /usr/local/Cellar/softhsm/2.5.0/lib/softhsm/libsofthsm2.so"
	storePath      string
	storeLabel     string // "ForFabric"
	pin            string // "98765432"
	softVerify     bool   // false
	msg            string
	iterations     int           // 100 times
	throttle       time.Duration // 2 sec
	throttleVerify time.Duration // 2 sec
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature against a key in HSM",
	Long: `This command allows testing the signing of a message using specific PKCS11 arguments. For example:

	pkcs11perf --msg "Hello World Message to Sign"`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("verify command executing ....")
		cs, err := getCryptoSuite()
		if err != nil {
			fmt.Println("Can't get CryptoSuite instance: ", err)
			os.Exit(1)
		}

		fmt.Println("	Generating new Key ..")
		n := time.Now()
		// generate key
		key, err := cs.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: true}) // make sure the key is temporary to avoid flooding the HSM store
		if err != nil {
			fmt.Println("Can't generate new key: ", err)
			os.Exit(1)
		}
		fmt.Println("	Generating new Key done .. time spent: ", time.Since(n))
		fmt.Println("	About to call Sign ", iterations, " times")
		n = time.Now()
		bytesArr := make([][]byte, iterations)
		for i := 0; i < iterations; i++ {
			fmt.Println("		Signing msg # ", i+1)
			bytesArr[i], err = cs.Sign(key, []byte(msg), nil)
			if err != nil {
				fmt.Println("		Can't sign message # ", i+1, ", error: ", err)
				os.Exit(1)
			}
			time.Sleep(throttle)
		}
		fmt.Println("	Sign was called ", iterations, " times .. time spent: ", time.Since(n))

		pubKey, err := key.PublicKey()
		if err != nil {
			fmt.Println("Can't get extract public key from private key: ", err)
			os.Exit(1)
		}

		fmt.Println("	About to verify Signatures ", iterations, " times")
		n = time.Now()
		for i := 0; i < iterations; i++ {
			fmt.Println("		Verifying signature of msg # ", i+1)
			v, err := cs.Verify(pubKey, bytesArr[i], []byte(msg), nil)
			if err != nil {
				fmt.Println("		Can't verify signed message # ", i+1, " with public key: ", err)
				os.Exit(1)
			}
			if !v {
				fmt.Println("		Can't verify signed message # ", i+1, " with public and no error returned")
				os.Exit(1)
			}
			time.Sleep(throttleVerify)
		}
		fmt.Println("	Verify was called ", iterations, " times .. time spent: ", time.Since(n))
		fmt.Println("verify command done.")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	verifyCmd.PersistentFlags().StringVarP(&hashAlgorithm, "hashAlgorithm", "g", "SHA2", "Security Algorithm (Default: \"SHA2\")")
	verifyCmd.PersistentFlags().IntVarP(&level, "level", "l", 256, "Security Level (Default: 256)")
	verifyCmd.PersistentFlags().StringVarP(&library, "library", "r", hsmLibs, fmt.Sprintf("HSM Library Path(s) (Default:\"%s\")", hsmLibs))
	verifyCmd.PersistentFlags().StringVarP(&storePath, "storePath", "s", "", "Store Path (Default: \"\"). It can be any available path.")
	verifyCmd.PersistentFlags().StringVarP(&storeLabel, "storeLabel", "b", "ForFabric", "Store Label (Default: \"ForFabric\")")
	verifyCmd.PersistentFlags().StringVarP(&pin, "pin", "p", "98765432", "Store Pin (Default: \"98765432\")")
	verifyCmd.PersistentFlags().BoolVarP(&softVerify, "softVerify", "v", true, "Soft Verify (Default: true)")
	verifyCmd.PersistentFlags().StringVarP(&msg, "msg", "m", "Hello World", "Message to Sign by BCCSP using a generated key (Default: \"Hello World\")")
	verifyCmd.PersistentFlags().IntVarP(&iterations, "iterations", "i", 100, "Number of times to run the PKCS11 Sign function (Default: 100)")
	verifyCmd.PersistentFlags().DurationVarP(&throttle, "throttle", "t", 0*time.Second, "Throttle between each PKCS11 Sign calls (Default: 0s, ie no throttling)")
	verifyCmd.PersistentFlags().DurationVarP(&throttleVerify, "throttleVerify", "y", 0*time.Second, "Throttle between each PKCS11 Verify calls (Default: 0s, ie no throttling)")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func getCryptoSuite() (core.CryptoSuite, error) {
	opts := getOptsByConfig()
	bccsp, err := getBCCSPFromOpts(opts)

	if err != nil {
		return nil, err
	}
	return &wrapper.CryptoSuite{BCCSP: bccsp}, nil
}

func getBCCSPFromOpts(pkcs11Opts *pkcs11.PKCS11Opts) (bccsp.BCCSP, error) {
	fOpts := &factory.FactoryOpts{Pkcs11Opts: pkcs11Opts, ProviderName: "PKCS11"}
	f := &factory.PKCS11Factory{}

	csp, err := f.Get(fOpts)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

//getOptsByConfig Returns Factory opts for given SDK config
func getOptsByConfig() *pkcs11.PKCS11Opts {
	pkks := pkcs11.FileKeystoreOpts{KeyStorePath: storePath} // if storePath is empty, then it's equivalent to opts.Ephemeral == true
	opts := &pkcs11.PKCS11Opts{
		SecLevel:     level,
		HashFamily:   hashAlgorithm,
		FileKeystore: &pkks,
		Library:      library,
		Pin:          pin,
		Label:        storeLabel,
		SoftVerify:   softVerify,
	}
	fmt.Println("Initialized PKCS11 cryptosuite")

	return opts
}
