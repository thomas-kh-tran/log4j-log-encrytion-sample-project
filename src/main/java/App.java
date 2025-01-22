

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.appender.SecureFileManager;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

/**
 * The {@code App} class provides an example use of the secure logging mechanism of
 * the log4j2-logging-framework-log-encryption branch with hash validation and log file encryption for log files.
 * It demonstrates logging, secure file decryption, and validation of log message hashes.
 * The logging attributes are set in log4j2.xml
 */
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        boolean useSalt = true; // true if using salt
        //Test log messages
        logger.info("This is a secure log message.");
        logger.error("Sensitive error data.");

        //If hashing enabled in XML
        checkHashes("C:\\log4j-secure-sample\\logs\\secure-log.log", useSalt);

        //If encryption enabled in XML
        String decryptedLog = SecureFileManager.decryptFile("C:\\log4j-secure-sample\\logs\\secure-log.log", "mySecretKey00000mySecretKey00000", "bG9nZW52aXJvbndh");
        System.out.println(decryptedLog);

        //If hashing and encryption enabled in XML
        checkHashesString(decryptedLog, useSalt);

    }

    // Helper functions
    /**
     * Validates the hash integrity of a log file's content.
     *
     * @param filePath The file path of the log file to validate.
     * @param useSalt  A boolean indicating whether to use a salt in hash computation.
     */
    private static void checkHashes(String filePath, boolean useSalt) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Split the line using the HASH_SEPARATOR ("||")
                String[] parts = line.split("\\|\\|");

                // Ensure the line has the expected number of parts
                if ((useSalt && parts.length == 3) || (!useSalt && parts.length == 2)) {
                    String message = parts[0].trim();
                    String extractedHash = parts[1].trim();
                    String salt = useSalt ? parts[2].trim() : "";

                    // Compute the hash using the message and salt (if applicable)
                    String computedHash = useSalt ? computeHash(message+salt) : computeHash(message);

                    // Compare the computed hash with the extracted hash
                    if (!computedHash.equals(extractedHash)) {
                        System.out.println("Hash does NOT match for message: " + message);
                        System.out.println("Expected: " + extractedHash);
                        System.out.println("Computed: " + computedHash);
                    }else{
                        System.out.println("Hash matches for message: " + message);
                    }
                } else {
                    // Invalid format: log or handle appropriately
                    System.out.println("Invalid format");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Validates the hash integrity of log content provided as a string.
     *
     * @param logContent The log content to validate.
     * @param useSalt    A boolean indicating whether to use a salt in hash computation.
     */
    public static void checkHashesString(String logContent, boolean useSalt) {
        String[] lines = logContent.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Split the line using the HASH_SEPARATOR ("||")
            String[] parts = line.split("\\|\\|");

            // Ensure the line has the expected number of parts
            if ((useSalt && parts.length == 3) || (!useSalt && parts.length == 2)) {
                String message = parts[0].trim();
                String extractedHash = parts[1].trim();
                String salt = useSalt ? parts[2].trim() : "";

                // Compute the hash using the message and salt (if applicable)
                String computedHash = useSalt ? computeHash(message+salt) : computeHash(message);

                // Compare the computed hash with the extracted hash
                if (!computedHash.equals(extractedHash)) {
                    System.out.println("Hash does NOT match for message: " + message);
                    System.out.println("Expected: " + extractedHash);
                    System.out.println("Computed: " + computedHash);
                }else{
                    System.out.println("Hash matches for message: " + message);
                }
            } else {
                // Invalid format: log or handle appropriately
                System.out.println("Invalid format");
            }
        }
    }

    /**
     * Computes the hash of a given String (UTF-8 encoded) with Algorithm SHA-256 using the default provider
     *
     * @param message The String to be hashed.
     */
    public static String computeHash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
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


