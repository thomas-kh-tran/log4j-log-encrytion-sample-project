

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.appender.SecureFileManager;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) throws GeneralSecurityException {
      //  System.out.println(Arrays.toString(deriveKey("mySecretKey", null).getEncoded()));

        logger.info("This is a secure log message.");
        logger.error("Sensitive error data.");
        checkHashes("C:\\log4j-secure-sample\\logs\\secure-log.log");
        String decryptedLog = SecureFileManager.decryptFile("C:\\log4j-secure-sample\\logs\\secure-log.log", "mySecretKey00000mySecretKey00000", "bG9nZW52aXJvbndh");
        System.out.println(decryptedLog);
        checkHashesString(decryptedLog);


    }
    public static void checkHashes(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Split the line using the HASH_SEPARATOR ("||")
                int separatorIndex = line.lastIndexOf("||");
                if (separatorIndex != -1) {
                    String message = line.substring(0, separatorIndex).trim();
                    String hashWithSeparators = line.substring(separatorIndex).trim();

                    // Validate hash format
                    if (hashWithSeparators.startsWith("||")) {
                        String extractedHash = hashWithSeparators.substring(2);

                        // Compute the hash of the message
                        String computedHash = computeHash(message);

                        // Compare the computed hash with the extracted hash
                        if (computedHash.equals(extractedHash)) {
                            System.out.println("Hash matches for message: " + message);
                        } else {
                            System.out.println("Hash does NOT match for message: " + message);
                            System.out.println("Expected: " + extractedHash);
                            System.out.println("Computed: " + computedHash);
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void checkHashesString(String logContent) {
        String[] lines = logContent.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Split the line using the HASH_SEPARATOR ("||")
            int separatorIndex = line.lastIndexOf("||");
            if (separatorIndex != -1) {
                String message = line.substring(0, separatorIndex).trim();
                String hashWithSeparators = line.substring(separatorIndex).trim();

                // Validate hash format
                if (hashWithSeparators.startsWith("||")) {
                    String extractedHash = hashWithSeparators.substring(2);

                    // Compute the hash of the message
                    String computedHash = computeHash(message);

                    // Compare the computed hash with the extracted hash
                    if (computedHash.equals(extractedHash)) {
                        System.out.println("STRING Hash matches for message: " + message);
                    } else {
                        System.out.println("STRING Hash does NOT match for message: " + message);
                        System.out.println("Expected: " + extractedHash);
                        System.out.println("Computed: " + computedHash);
                    }
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


