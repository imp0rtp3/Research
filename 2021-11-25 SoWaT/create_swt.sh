#! /bin/bash
echo '#!/usr/bin/env python3
import socket
import sys
print("Swt called with args: {}".format(", ".join(sys.argv[1:])))

"""
' > swt
cd certs
cat cert.pem server-key.pem server-cert.pem >> ../swt
echo '"""' >> ../swt