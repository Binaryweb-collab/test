// Networking & IO
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

// Java Swing for GUI
import javax.swing.*;

// Java AWT (Only Required Components)
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

// Cryptography (AES-GCM Encryption)
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class ChatClientGUI {
    private static final String HOST = "localhost";
    private static final int PORT = 2013;
    private static final byte[] AES_KEY = "0123456789abcdef0123456789abcdef".getBytes(); // 256-bit key
    private static final int IV_LENGTH = 12; // 96-bit IV for AES-GCM
    private static final int HEARTBEAT_INTERVAL = 5;

    static class User {
        String name;
        int id;
        boolean isOnline;

        User(int id, String name) {
            this.id = id;
            this.name = name;
            this.isOnline = true;
        }
    }

    private static int myId = -1;
    private static String myUsername;
    private static final List<User> users = Collections.synchronizedList(new ArrayList<>());
    private static final Map<String, List<String>> privateMessages = new ConcurrentHashMap<>();
    private static Socket socket;
    private static PrintWriter out;
    private static BufferedReader in;

    // GUI Components
    private static JFrame frame;
    private static JList<String> userList;
    private static DefaultListModel<String> userListModel;
    private static JTextArea publicChatArea;
    private static JTextField messageField;
    private static JTabbedPane privateChatTabs;
    private static Map<String, JTextArea> privateChatAreas = new HashMap<>();

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java ChatClientGUI <username>");
            return;
        }
        myUsername = args[0];
        initializeGUI();
        connectToServer();
    }

    private static void initializeGUI() {
        frame = new JFrame("Chat - " + myUsername);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 600);
        frame.setLayout(new BorderLayout());

        // User List Panel (Left)
        userListModel = new DefaultListModel<>();
        userList = new JList<>(userListModel);
        userList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) { // Double-click to open private chat
                    String selectedUser = userList.getSelectedValue();
                    if (selectedUser != null && !selectedUser.equals(myUsername)) {
                        openPrivateChatTab(selectedUser);
                    }
                }
            }
        });
        JScrollPane userScrollPane = new JScrollPane(userList);
        userScrollPane.setPreferredSize(new Dimension(200, 0));
        frame.add(userScrollPane, BorderLayout.WEST);

        // Chat Area (Center)
        privateChatTabs = new JTabbedPane();
        publicChatArea = new JTextArea();
        publicChatArea.setEditable(false);
        JScrollPane publicChatScroll = new JScrollPane(publicChatArea);
        privateChatTabs.addTab("Public Chat", publicChatScroll);
        frame.add(privateChatTabs, BorderLayout.CENTER);

        // Input Panel (Bottom)
        JPanel inputPanel = new JPanel(new BorderLayout());
        messageField = new JTextField();
        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendMessage());
        inputPanel.add(messageField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        frame.add(inputPanel, BorderLayout.SOUTH);

        frame.setVisible(true);
    }

    private static void connectToServer() {
        try {
            socket = new Socket(HOST, PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            out.println("JOIN:" + myUsername);

            new Thread(ChatClientGUI::sendHeartbeat).start();
            new Thread(ChatClientGUI::receiveMessages).start();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(frame, "Failed to connect: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void receiveMessages() {
        try {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("ASSIGNED_ID:")) {
                    myId = Integer.parseInt(line.substring(12));
                    SwingUtilities.invokeLater(() -> frame.setTitle("Chat - " + myUsername + " (ID: " + myId + ")"));
                } else if (line.startsWith("CHAT:")) {
                    String message = decrypt(line.substring(5));
                    SwingUtilities.invokeLater(() -> publicChatArea.append(message + "\n"));
                } else if (line.startsWith("PRIVATE:")) {
                    String message = decrypt(line.substring(8));
                    String[] parts = message.split(":", 2);
                    String sender = parts[0];
                    String text = parts[1];
                    String queueKey = sender.equals(myUsername) ? myUsername + ":" + text.split(" ")[0] : sender + ":" + myUsername;
                    privateMessages.computeIfAbsent(queueKey, k -> new ArrayList<>()).add("[PRIVATE] " + message);
                    SwingUtilities.invokeLater(() -> {
                        openPrivateChatTab(sender);
                        JTextArea chatArea = privateChatAreas.get(sender);
                        if (chatArea != null) {
                            chatArea.append("[PRIVATE] " + message + "\n");
                        }
                    });
                } else if (line.startsWith("USERLIST:")) {
                    String decryptedList = decrypt(line.substring(9));
                    updateUserList(decryptedList);
                } else if (line.startsWith("ERROR:")) {
                    String error = line.substring(6);
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(frame, error));
                }
            }
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(frame, "Connection lost: " + e.getMessage()));
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
            users.clear();
            userListModel.clear();
            if (userList.startsWith("USERLIST:")) {
                userList = userList.substring(9);
            }
            if (userList.trim().isEmpty()) return;

            String[] entries = userList.split(";");
            for (String entry : entries) {
                String[] parts = entry.split(":");
                if (parts.length < 2) continue;
                int id = Integer.parseInt(parts[0].trim());
                String name = parts[1].trim();
                users.add(new User(id, name));
                userListModel.addElement(name);
            }
        }
    }

    private static void sendMessage() {
        String input = messageField.getText().trim();
        if (input.isEmpty()) return;

        int selectedTab = privateChatTabs.getSelectedIndex();
        if (selectedTab == 0) { // Public chat tab
            String encryptedMessage = encrypt(myUsername + ":" + input);
            out.println("CHAT:" + encryptedMessage);
            publicChatArea.append("[You]: " + input + "\n");
        } else { // Private chat tab
            String receiver = privateChatTabs.getTitleAt(selectedTab);
            String encryptedMessage = encrypt(myUsername + ":" + input);
            out.println("PRIVATE:" + receiver + ":" + encryptedMessage);
            JTextArea chatArea = privateChatAreas.get(receiver);
            if (chatArea != null) {
                chatArea.append("[You to " + receiver + "]: " + input + "\n");
            }
            String queueKey = myUsername + ":" + receiver;
            privateMessages.computeIfAbsent(queueKey, k -> new ArrayList<>()).add("[You to " + receiver + "]: " + input);
        }
        messageField.setText("");
    }

    private static void openPrivateChatTab(String user) {
        if (privateChatAreas.containsKey(user) || user.equals(myUsername)) return;

        JTextArea chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        privateChatTabs.addTab(user, scrollPane);
        privateChatAreas.put(user, chatArea);

        // Load existing messages
        String queueKey = myUsername.compareTo(user) < 0 ? myUsername + ":" + user : user + ":" + myUsername;
        List<String> history = privateMessages.get(queueKey);
        if (history != null) {
            for (String msg : history) {
                chatArea.append(msg + "\n");
            }
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