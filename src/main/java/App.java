

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.appender.SecureFileManager;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) throws GeneralSecurityException {
      //  System.out.println(Arrays.toString(deriveKey("mySecretKey", null).getEncoded()));

        logger.info("This is a secure log message.");
        logger.error("Sensitive error data.");
        checkHashes("C:\\log4j-secure-sample\\logs\\secure-log.log");
        String decryptedLog = SecureFileManager.decryptFile("C:\\log4j-secure-sample\\logs\\secure-log.log", "mySecretKey00000mySecretKey00000", "bG9nZW52aXJvbndh");
        checkHashesString(decryptedLog);

        System.out.println(decryptedLog);

    }
    public static void checkHashes(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Check if the line contains a log message
                //System.out.println(line);
                // Read the next line for the hash
                    String hashLine = br.readLine();
                    if (hashLine != null && hashLine.startsWith("||") && hashLine.endsWith("||")) {
                        String hash = hashLine.substring(2, hashLine.length() - 2); // Remove the ||
                        //System.out.println(hash);
                        // Compute the hash of the message
                        String computedHash = computeHash(line+"\r\n");

                        // Compare the computed hash with the provided hash
                        if (computedHash.equals(hash)) {
                            System.out.println("Hash matches for message: " + line);
                        } else {
                            System.out.println("Hash does NOT match for message: " + line);
                            System.out.println(computedHash);
                        }
                    }

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void checkHashesString(String logContent) {
        String[] lines = logContent.split("\n");
        for (int i = 0; i < lines.length; i=i+2) {
            // Check if the line contains a log message
                String message = lines[i].trim();

                // Check if the next line exists for the hash
                if (i + 1 < lines.length && lines[i + 1].startsWith("||") && lines[i + 1].endsWith("||")) {
                    String hash = lines[i + 1].substring(2, lines[i + 1].length() - 2); // Remove the ||

                    // Compute the hash of the message
                    String computedHash = computeHash(message+"\r\n");

                    // Compare the computed hash with the provided hash
                    if (computedHash.equals(hash)) {
                        System.out.println("STRING Hash matches for message: " + message);
                    } else {
                        System.out.println("STRING Hash does NOT match for message: " + message);
                    }
                }

        }
    }

    public static String computeHash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}


