

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

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) throws GeneralSecurityException {
      //  System.out.println(Arrays.toString(deriveKey("mySecretKey", null).getEncoded()));
        boolean useSalt = true;
        logger.info("This is a secure log messageä.");
        logger.error("Sensitive error data.");
        checkHashes("C:\\log4j-secure-sample\\logs\\secure-log.log", useSalt);
        String decryptedLog = SecureFileManager.decryptFile("C:\\log4j-secure-sample\\logs\\secure-log.log", "mySecretKey00000mySecretKey00000", "bG9nZW52aXJvbndh");
        System.out.println(decryptedLog);
        checkHashesString(decryptedLog, useSalt);


    }
    // Helper functions
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


