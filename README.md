#### pkcs11perf binary to test PKCS11 key loading from HSM and signature verification

Prerequisites:
- nothing

##### Build and run binary...
```
$ make all
$ make test
```


you may need to to grand access to the scripts used in the makefile, to do so run the following:
chmod 755 scripts/build.sh 
chmod 755 scripts/test.sh


##### To run the binary with different values you can run the binary directly
```
$./pkcs11perf verify --msg "hello world" --storePath "/tmp/msp" --hashAlgorithm "SHA2" --level 256 \
--library "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/softhsm/libsofthsm2.so,/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so,/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so, /usr/local/Cellar/softhsm/2.5.0/lib/softhsm/libsofthsm2.so" \
--storeLabel "ForFabric" --pin "123456789" --softVerify true --iterations 1000 --throttle 1s --throttleVerify 1s
```

##### binary arguments:
	--hashAlgorithm or -g   Default: "SHA2"
	--level or -l           Default: 256
	--library or -r         Default: full path in the above command is the default value
	--storePath or -s       Default: "". It can be any locally available path.
	--storeLabel or -b      Default: "ForFabric"
	--pin or -p             Default: "98765432"
	--softVerify or -v      Default: false
	--msg or -m             Default: "Hello World"
	--iterations or -i      Default: 100
	--throttle or -t        Default: 0s, ie no throttling
	--throttleVerify or -y  Default: 0s, ie no throttling