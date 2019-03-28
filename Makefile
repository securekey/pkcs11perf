#  Copyright SecureKey Technologies Inc.
#  This file contains software code that is the intellectual property of SecureKey.
#  SecureKey reserves all rights in the code and you may not use it without
#	 written permission from SecureKey.

# Supported Targets:
# all : runs build
# test : runs simple empty commad

all:
	@scripts/build.sh

test:
	@scripts/test.sh

# delete the binary ( NOT the project :-) )
clean:
	rm -f ./pkcs11perf