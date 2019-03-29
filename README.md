#### pkcs11perf binary to test PKCS11 key loading from HSM and signature verification

Prerequisites:
- nothing

##### Build and run binary...
```
$ make all
$ make test
```

<<<<<<< HEAD
###### build failure and how to fix it
since the time/rate package is not playing nice with go mod, you might have to install this package manually.

make all output:
cmd/verify.go:20:2: cannot find package "golang.org/x/time/rate" in any of:
	/usr/local/Cellar/go/1.12/libexec/src/golang.org/x/time/rate (from $GOROOT)
	/YOUR/GOPATH/src/golang.org/x/time/rate (from $GOPATH)
chmod: pkcs11perf: No such file or directory
make: *** [all] Error 1

to fix this locally simply run:
```
$ GO111MODULE=on go get golang.org/x/time/rate
$ make all
```


You may need to to grant access to the scripts used in the makefile the binary, to do so run the following:
chmod 755 scripts/build.sh 
chmod 755 scripts/test.sh

after make all and before make test, grant access to the generated binary:
chmod 755 pkcs11perf


##### To run the binary with different values you can run the binary directly
```
$./pkcs11perf verify --msg "hello world" --storePath "/tmp/msp" --hashAlgorithm "SHA2" --level 256 \
--library "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/softhsm/libsofthsm2.so,/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so, /usr/local/Cellar/softhsm/2.5.0/lib/softhsm/libsofthsm2.so" \
--storeLabel "ForFabric" --pin "123456789" --softVerify true --iterations 1000 --concurrencyLimitSign 50 --burstSign 5 --concurrencyLimitVerify 50 --burstVerify 5 --signDelay 1s --verifyDelay 1s
```

##### binary arguments:
 Available arguments are:
	--hashAlgorithm or -g           Security Algorithm      Default: "SHA2"
	--level or -l                   Security Level          Default: 256
	--library or -r                 HSM Library Path(s)     Default: full path in the above command is the default value
	--storePath or -s               Store Path              Default: "". It can be any locally available path.
	--storeLabel or -b              Store Label             Default: "ForFabric"
	--pin or -p                     Store Pin               Default: "98765432"
	--softVerify or -v              Soft Verify             Default: false
	--msg or -m                     Message to Sign by BCCSP using a generated key  Default: "Hello World"
	--iterations or -i              Number of times to run the PKCS11 Sign function Default: 100
	--concurrencyLimitSign or -c    Concurrency Limit of Sign function              Default: 50
	--burstSign or -b               # of Burst calls of Sign function               Default: 5
	--concurrencyLimitVerify or -f  Concurrency Limit of Verify function            Default: 50
	--burstVerify or -e             # of Burst calls of Verify function             Default: 5
	--signDelay or -t               Delay between each PKCS11 Sign function         Default: 0s
	--verifyDelay or -y             Delay between each PKCS11 Verify function       Default: 0s
