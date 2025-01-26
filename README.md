# Sample Project Overview

This sample project demonstrates logging, secure file encryption (AES CTR mode) and decryption, as well as hashing (SHA-256 with/without Salt) and validation of log message based on the [log4j2-logging-framework-log-encryption](https://github.com/thomas-kh-tran/logging-log4j2-log-encryption) fork (secure-logging branch).

## Prerequisites

1. Working installation of log4j with log encryption functionality
If the fork is merged into the main repositoty you can skip steps 1 and 2.
   1. Clone the repository: [log4j2-logging-framework-log-encryption](https://github.com/thomas-kh-tran/logging-log4j2-log-encryption) (secure-logging branch)
   2. Install via: `mvn install -pl log4j-core -DskipTests`
   3. Adjust project `pom.xml` to the corresponding log4j version

## Use

1. Adjust `log4j2.xml` to suit your needs
2. Run the main application

## Troubleshooting

1. Check your security providers by executing Security.getProviders() 
2. Try using the default provider (SUN)
3. Some Providers(for example BouncyCastle) don't work with the currently implemented AES CTR mode,
 see [here](https://stackoverflow.com/questions/16292694/simulating-a-stream-cipher-with-aes-ctr).
 This is likely attributable to its use of a BufferedOutputStream.
