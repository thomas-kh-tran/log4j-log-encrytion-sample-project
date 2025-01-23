# Sample Project Overview

This sample project demonstrates logging, secure file encryption and decryption, as well as validation of log message hashes based on the [log4j2-logging-framework-log-encryption](https://github.com/thomas-kh-tran/logging-log4j2-log-encryption) fork.

## Prerequisites

1. Working installation of log4j with log encryption functionality
   1. Clone the repository: [log4j2-logging-framework-log-encryption](https://github.com/thomas-kh-tran/logging-log4j2-log-encryption)
   2. Install via: `mvn install -pl log4j-core -DskipTests`
   3. Adjust project `pom.xml` to the corresponding log4j version

## Use

1. Adjust `log4j2.xml` to suit your needs
2. Run the main application

##Troubleshooting

1. Check your security provider by executing Security.getProviders() 
2. Try using the default provider (SUN)
3. Some Providers don't work with the currently implemented AES CTR mode,
 see [here](https://stackoverflow.com/questions/16292694/simulating-a-stream-cipher-with-aes-ctr) 
 This is likely attributable to its use of a BufferedOutputStream.