#!/bin/bash
#
# Copyright SecureKey Technologies Inc.
# This file contains software code that is the intellectual property of SecureKey.
# SecureKey reserves all rights in the code and you may not use it without written permission from SecureKey.
#


GO111MODULE=on go build -tags pkcs11 -o pkcs11perf
chmod 755 pkcs11perf


