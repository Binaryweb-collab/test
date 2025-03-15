import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;


public class ChatClient {
    private static final String HOST = "localhost";
    private static final int PORT = 2013;
    private static final byte[] AES_KEY = "0123456789abcdef0123456789abcdef".getBytes(); // 256-bit key
    private static final int IV_LENGTH = 12; // Recommended 96-bit IV for AES-GCM
    private static final int HEARTBEAT_INTERVAL = 5;

    static class User {
        String name;
        int id;
        boolean isOnline;
        long lastActive;

        User(int id, String name) {
            this.id = id;
            this.name = name;
            this.isOnline = true;
            this.lastActive = System.currentTimeMillis() / 1000;
        }
    }

    private static int myId = -1;
    private static String myUsername;
    private static final List<User> users = Collections.synchronizedList(new ArrayList<>());
    private static final List<String> messages = Collections.synchronizedList(new ArrayList<>());
    // Map to store private message history per user pair
    private static final Map<String, List<String>> privateMessages = new ConcurrentHashMap<>();
    private static Socket socket;
    private static PrintWriter out;
    private static BufferedReader in;

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.out.println("Usage: java ChatClient <username>");
            return;
        }
        myUsername = args[0];

        socket = new Socket(HOST, PORT);
        out = new PrintWriter(socket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        out.println("JOIN:" + myUsername);

        new Thread(ChatClient::sendHeartbeat).start();
        new Thread(ChatClient::receiveMessages).start();

        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        String input;
        while ((input = console.readLine()) != null) {
            if (input.startsWith("/")) {
                processCommand(input);
            } else if (!input.trim().isEmpty()) {
                String encryptedMessage = encrypt(myUsername + ":" + input.trim());
                out.println("CHAT:" + encryptedMessage);
                messages.add("[You]: " + input);
            }
        }

        out.println("EXIT");
        socket.close();
    }

    private static void receiveMessages() {
        try {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("ASSIGNED_ID:")) {
                    myId = Integer.parseInt(line.substring(12));
                    System.out.println("Connected as " + myUsername + " (ID: " + myId + ")");
                } else if (line.startsWith("CHAT:")) {
                    String message = decrypt(line.substring(5));
                    System.out.println(message);
                    messages.add(message);
                } else if (line.startsWith("PRIVATE:")) {
                    String message = decrypt(line.substring(8));
                    String[] parts = message.split(":", 2);
                    String sender = parts[0];
                    String text = parts[1];
                    String queueKey = (sender.equals(myUsername)) ? myUsername + ":" + text.split(" ")[0] : sender + ":" + myUsername;
                    privateMessages.computeIfAbsent(queueKey, k -> new ArrayList<>()).add("[PRIVATE] " + message);
                    System.out.println("[PRIVATE] " + message);
                } else if (line.startsWith("USERLIST:")) {
                    String decryptedList = decrypt(line.substring(9));
                    updateUserList(decryptedList);
                } else if (line.startsWith("ERROR:")) {
                    System.out.println(line.substring(6));
                }
            }
        } catch (Exception e) {
            System.out.println("Connection lost: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void sendHeartbeat() {
        while (true) {
            out.println("HEARTBEAT");
            try {
                Thread.sleep(HEARTBEAT_INTERVAL * 1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void updateUserList(String userList) {
        synchronized (users) {
            users.forEach(u -> u.isOnline = false);
            if (userList == null || userList.trim().isEmpty()) {
                System.out.println("[CLIENT] No users online.");
                return;
            }
            if (userList.startsWith("USERLIST:")) {
                userList = userList.substring(9);
            }
            String[] entries = userList.split(";");
            for (String entry : entries) {
                String[] parts = entry.split(":");
                if (parts.length < 2) continue;
                try {
                    int id = Integer.parseInt(parts[0].trim());
                    String name = parts[1].trim();
                    users.removeIf(u -> u.id == id);
                    users.add(new User(id, name));
                } catch (NumberFormatException e) {
                    System.err.println("[CLIENT] Warning: Skipping invalid user entry: " + entry);
                }
            }
        }
    }

    private static void processCommand(String input) {
        if (input.equals("/quit")) {
            out.println("EXIT");
            System.exit(0);
        } else if (input.equals("/users")) {
            synchronized (users) {
                System.out.println("Online users:");
                for (User user : users) {
                    if (user.isOnline) {
                        System.out.println("  " + user.name + " (ID: " + user.id + ")");
                    }
                }
            }
        } else if (input.startsWith("/pm ")) {
            String[] parts = input.substring(4).split(" ", 2);
            if (parts.length == 2) {
                String receiver = parts[0];
                String message = parts[1];
                String encryptedMessage = encrypt(myUsername + ":" + message);
                out.println("PRIVATE:" + receiver + ":" + encryptedMessage);
                String queueKey = myUsername + ":" + receiver;
                privateMessages.computeIfAbsent(queueKey, k -> new ArrayList<>()).add("[PRIVATE to " + receiver + "]: " + message);
                System.out.println("[PRIVATE to " + receiver + "]: " + message);
            } else {
                System.out.println("Usage: /pm <username> <message>");
            }
        } else if (input.startsWith("/pmlist ")) {
            String[] parts = input.split(" ", 2);
            if (parts.length == 2) {
                String otherUser = parts[1];
                String queueKey = myUsername.compareTo(otherUser) < 0 ? myUsername + ":" + otherUser : otherUser + ":" + myUsername;
                List<String> pms = privateMessages.getOrDefault(queueKey, Collections.emptyList());
                if (pms.isEmpty()) {
                    System.out.println("[CLIENT] No private messages with " + otherUser + ".");
                } else {
                    System.out.println("=== Private Messages with " + otherUser + " ===");
                    pms.forEach(System.out::println);
                }
            } else {
                System.out.println("Usage: /pmlist <username>");
            }
        } else {
            System.out.println("Unknown command: " + input);
        }
    }

    private static String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            byte[] encryptedMessage = new byte[IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, encryptedMessage, 0, IV_LENGTH);
            System.arraycopy(encrypted, 0, encryptedMessage, IV_LENGTH, encrypted.length);
            return Base64.getEncoder().encodeToString(encryptedMessage);
        } catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    private static String decrypt(String ciphertext) {
        try {
            byte[] decodedMessage = Base64.getDecoder().decode(ciphertext);
            byte[] iv = Arrays.copyOfRange(decodedMessage, 0, IV_LENGTH);
            byte[] encrypted = Arrays.copyOfRange(decodedMessage, IV_LENGTH, decodedMessage.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }
}