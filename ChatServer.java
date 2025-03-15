import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ChatServer {
    private static final int PORT = 2013;
    private static final int MAX_USERS = 20;
    private static final byte[] AES_KEY = "0123456789abcdef0123456789abcdef".getBytes(); // 256-bit key
    private static final int IV_LENGTH = 12; // 96-bit IV for GCM

    static class User {
        String name;
        int id;
        long lastActive;
        boolean isOnline;
        PrintWriter out;

        User(String name, int id, PrintWriter out) {
            this.name = name;
            this.id = id;
            this.lastActive = System.currentTimeMillis() / 1000;
            this.isOnline = true;
            this.out = out;
        }
    }

    private static final List<User> users = Collections.synchronizedList(new ArrayList<>());
    // Map to store private message queues: key is "sender:receiver", value is a queue of messages
    private static final Map<String, Queue<String>> privateQueues = new ConcurrentHashMap<>();
    private static int nextUserId = 1;

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("[SERVER] Starting chat server on port " + PORT);

        new Thread(ChatServer::monitorUsers).start();

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(() -> handleClient(clientSocket)).start();
        }
    }

    private static void handleClient(Socket socket) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String joinMessage = in.readLine();
            if (joinMessage != null && joinMessage.startsWith("JOIN:")) {
                String username = joinMessage.substring(5);
                int id;
                synchronized (users) {
                    if (users.size() >= MAX_USERS) {
                        out.println("ERROR:Max users reached");
                        return;
                    }
                    id = addUser(username, out);
                    out.println("ASSIGNED_ID:" + id);
                    sendUserList();
                }

                String line;
                while ((line = in.readLine()) != null) {
                    if (line.startsWith("CHAT:")) {
                        String encryptedMessage = line.substring(5);
                        String message = decrypt(encryptedMessage);
                        broadcastMessage(username, message, id);
                        updateUserActivity(username);
                    } else if (line.startsWith("PRIVATE:")) {
                        String[] parts = line.substring(8).split(":", 2);
                        String receiver = parts[0];
                        String encryptedMessage = parts[1];
                        String message = decrypt(encryptedMessage);
                        handlePrivateMessage(username, receiver, message, id, out);
                        updateUserActivity(username);
                    } else if (line.equals("HEARTBEAT")) {
                        updateUserActivity(username);
                    } else if (line.equals("EXIT")) {
                        removeUser(username);
                        sendUserList();
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("[SERVER] Client error: " + e.getMessage());
        }
    }

    private static void handlePrivateMessage(String sender, String receiver, String message, int senderId, PrintWriter senderOut) {
        String queueKey = sender + ":" + receiver;
        String encryptedMessage = encrypt(sender + ":" + message);
        String msg = "PRIVATE:" + encryptedMessage;

        synchronized (users) {
            User target = users.stream().filter(u -> u.name.equals(receiver) && u.isOnline).findFirst().orElse(null);
            if (target != null) {
                // Add to private queue
                privateQueues.computeIfAbsent(queueKey, k -> new LinkedList<>()).add(message);
                // Send to receiver
                target.out.println(msg);
                // Echo back to sender
                if (target.id != senderId) senderOut.println(msg);
                System.out.println("[PRIVATE] " + sender + " to " + receiver + ": " + message);
            } else {
                senderOut.println("ERROR:User " + receiver + " is not online");
                System.out.println("[SERVER] Failed to send private message from " + sender + " to " + receiver + ": offline");
            }
        }
    }

    private static int addUser(String name, PrintWriter out) {
        synchronized (users) {
            for (User user : users) {
                if (user.name.equals(name)) {
                    user.isOnline = true;
                    user.lastActive = System.currentTimeMillis() / 1000;
                    user.out = out;
                    return user.id;
                }
            }
            int id = nextUserId++;
            users.add(new User(name, id, out));
            System.out.println("[SERVER] User " + name + " joined with ID " + id);
            return id;
        }
    }

    private static void removeUser(String name) {
        synchronized (users) {
            users.stream().filter(u -> u.name.equals(name)).findFirst()
                .ifPresent(u -> u.isOnline = false);
        }
        System.out.println("[SERVER] User " + name + " left");
    }

    private static void updateUserActivity(String name) {
        synchronized (users) {
            users.stream().filter(u -> u.name.equals(name)).findFirst()
                .ifPresent(u -> {
                    u.lastActive = System.currentTimeMillis() / 1000;
                    u.isOnline = true;
                });
        }
    }

    private static void broadcastMessage(String sender, String message, int senderId) {
        String encryptedMessage = encrypt(sender + ":" + message);
        String msg = "CHAT:" + encryptedMessage;
        synchronized (users) {
            for (User user : users) {
                if (user.isOnline && user.id != senderId) {
                    user.out.println(msg);
                }
            }
        }
        System.out.println("[CHAT] " + sender + ": " + message);
    }

    private static void sendUserList() {
        StringBuilder list = new StringBuilder("USERLIST:");
        synchronized (users) {
            for (User user : users) {
                if (user.isOnline) {
                    list.append(user.id).append(":").append(user.name).append(";");
                }
            }
        }
        if (list.length() > 9) list.setLength(list.length() - 1);
        String encryptedList = encrypt(list.toString());
        synchronized (users) {
            for (User user : users) {
                if (user.isOnline) {
                    user.out.println("USERLIST:" + encryptedList);
                }
            }
        }
    }

    private static void monitorUsers() {
        while (true) {
            long now = System.currentTimeMillis() / 1000;
            boolean changed = false;
            synchronized (users) {
                for (User user : users) {
                    if (user.isOnline && (now - user.lastActive > 15)) {
                        user.isOnline = false;
                        System.out.println("[SERVER] User " + user.name + " (ID #" + user.id + ") timed out");
                        changed = true;
                    }
                }
            }
            if (changed) sendUserList();
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    private static String decrypt(String ciphertextWithIV) {
        try {
            byte[] decoded = Base64.getDecoder().decode(ciphertextWithIV);
            byte[] iv = Arrays.copyOfRange(decoded, 0, IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(decoded, IV_LENGTH, decoded.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }
}