// Networking & IO
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

// GUI Libraries (Swing & AWT)
import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;

// Layout Managers & Components
import java.awt.FlowLayout;
import java.awt.BorderLayout;

// Cryptography (AES-GCM)
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Image Handling
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;


public class ChatClientGUI1 {
    private static final String HOST = "localhost";
    private static final int PORT = 2013;
    private static final byte[] AES_KEY = "0123456789abcdef0123456789abcdef".getBytes();
    private static final int IV_LENGTH = 12;

    // UI Colors and Fonts
    private static final Color PRIMARY_COLOR = new Color(52, 152, 219);
    private static final Color SECONDARY_COLOR = new Color(236, 240, 241);
    private static final Color ACCENT_COLOR = new Color(46, 204, 113);
    private static final Color TEXT_COLOR = new Color(52, 73, 94);
    private static final Font DEFAULT_FONT = new Font("Segoe UI", Font.PLAIN, 14);
    private static final Font BOLD_FONT = new Font("Segoe UI", Font.BOLD, 14);
    private static final Font SMALL_FONT = new Font("Segoe UI", Font.PLAIN, 12);

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
    private static JButton sendButton;
    private static JLabel statusLabel;
    private static JPanel contentPanel;

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (args.length != 1) {
            myUsername = JOptionPane.showInputDialog(null, "Enter your username:",
                    "Chat Login", JOptionPane.QUESTION_MESSAGE);
            if (myUsername == null || myUsername.trim().isEmpty()) {
                JOptionPane.showMessageDialog(null, "Username is required.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                System.exit(0);
            }
        } else {
            myUsername = args[0];
        }

        SwingUtilities.invokeLater(() -> {
            initializeGUI();
            connectToServer();
        });
    }

    private static void initializeGUI() {
        frame = new JFrame("Chat - " + myUsername);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000, 700);
        frame.setMinimumSize(new Dimension(800, 500));
        frame.setLocationRelativeTo(null);

        ImageIcon frameIcon = new ImageIcon(createImageIcon("C", PRIMARY_COLOR, Color.WHITE));
        frame.setIconImage(frameIcon.getImage());

        contentPanel = new JPanel(new BorderLayout(5, 5));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        contentPanel.setBackground(SECONDARY_COLOR);

        JPanel leftPanel = createUserListPanel();
        JPanel centerPanel = createChatPanel();
        JPanel statusPanel = createStatusPanel();

        contentPanel.add(leftPanel, BorderLayout.WEST);
        contentPanel.add(centerPanel, BorderLayout.CENTER);
        contentPanel.add(statusPanel, BorderLayout.SOUTH);

        frame.setContentPane(contentPanel);
        frame.setVisible(true);

        messageField.requestFocusInWindow();

        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                disconnect();
            }
        });
    }

    private static JPanel createUserListPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 5));
        panel.setBackground(SECONDARY_COLOR);
        panel.setPreferredSize(new Dimension(200, 0));

        JLabel usersHeader = new JLabel("Online Users", JLabel.CENTER);
        usersHeader.setFont(BOLD_FONT);
        usersHeader.setForeground(TEXT_COLOR);
        usersHeader.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(189, 195, 199)),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        userListModel = new DefaultListModelEdition<String>();
        userList = new JList<>(userListModel);
        userList.setFont(DEFAULT_FONT);
        userList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userList.setBackground(Color.WHITE);
        userList.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        userList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    String selectedUser = userList.getSelectedValue();
                    if (selectedUser != null && !selectedUser.equals(myUsername)) {
                        openPrivateChatTab(selectedUser);
                        privateChatTabs.setSelectedIndex(getTabIndex(selectedUser));
                    }
                }
            }
        });

        JScrollPane userScrollPane = new JScrollPane(userList);
        userScrollPane.setBorder(BorderFactory.createEmptyBorder());

        JPopupMenu userPopupMenu = new JPopupMenu();
        JMenuItem privateChat = new JMenuItem("Private Chat");
        privateChat.setFont(DEFAULT_FONT);
        privateChat.addActionListener(e -> {
            String selectedUser = userList.getSelectedValue();
            if (selectedUser != null && !selectedUser.equals(myUsername)) {
                openPrivateChatTab(selectedUser);
                privateChatTabs.setSelectedIndex(getTabIndex(selectedUser));
            }
        });
        userPopupMenu.add(privateChat);
        userList.setComponentPopupMenu(userPopupMenu);

        panel.add(usersHeader, BorderLayout.NORTH);
        panel.add(userScrollPane, BorderLayout.CENTER);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 0, 1, new Color(189, 195, 199)),
                BorderFactory.createEmptyBorder(0, 0, 0, 5)));

        return panel;
    }

    private static JPanel createChatPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 5));
        panel.setBackground(SECONDARY_COLOR);

        privateChatTabs = new JTabbedPane(JTabbedPane.TOP);
        privateChatTabs.setFont(DEFAULT_FONT);
        privateChatTabs.setBackground(Color.WHITE);

        publicChatArea = createChatTextArea();
        JScrollPane publicChatScroll = new JScrollPane(publicChatArea);
        publicChatScroll.setBorder(BorderFactory.createEmptyBorder());

        JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabPanel.setOpaque(false);
        JLabel tabLabel = new JLabel("Public Chat");
        tabLabel.setFont(DEFAULT_FONT);
        tabLabel.setIcon(new ImageIcon(createImageIcon("P", PRIMARY_COLOR, Color.WHITE)));
        tabPanel.add(tabLabel);

        privateChatTabs.addTab(null, publicChatScroll);
        privateChatTabs.setTabComponentAt(0, tabPanel);

        JPanel inputPanel = new JPanel(new BorderLayout(5, 0));
        inputPanel.setBackground(SECONDARY_COLOR);
        inputPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

        messageField = new JTextField();
        messageField.setFont(DEFAULT_FONT);
        messageField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(189, 195, 199)),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)));

        sendButton = new JButton("Send");
        sendButton.setFont(BOLD_FONT);
        sendButton.setBackground(PRIMARY_COLOR);
        sendButton.setForeground(Color.WHITE);
        sendButton.setFocusPainted(false);
        sendButton.setBorder(BorderFactory.createEmptyBorder(8, 16, 8, 16));
        sendButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        sendButton.addActionListener(e -> sendMessage());

        messageField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    sendMessage();
                }
            }
        });

        JButton emojiButton = new JButton("😊");
        emojiButton.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 16));
        emojiButton.setBackground(Color.WHITE);
        emojiButton.setFocusPainted(false);
        emojiButton.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        String[] commonEmojis = {"😊", "👍", "❤️", "😂", "🎉", "👋", "😎", "🙏", "🔥", "✅"};
        emojiButton.addActionListener(e -> {
            JPopupMenu emojiMenu = new JPopupMenu();
            for (String emoji : commonEmojis) {
                JMenuItem item = new JMenuItem(emoji);
                item.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 16));
                item.addActionListener(evt -> {
                    messageField.setText(messageField.getText() + item.getText());
                    messageField.requestFocusInWindow();
                });
                emojiMenu.add(item);
            }
            emojiMenu.show(emojiButton, 0, -emojiMenu.getPreferredSize().height);
        });

        JPanel extraButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        extraButtonsPanel.setBackground(SECONDARY_COLOR);
        extraButtonsPanel.add(emojiButton);
        inputPanel.add(extraButtonsPanel, BorderLayout.WEST);
        inputPanel.add(messageField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);

        panel.add(privateChatTabs, BorderLayout.CENTER);
        panel.add(inputPanel, BorderLayout.SOUTH);

        return panel;
    }

    private static JPanel createStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(SECONDARY_COLOR);
        panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

        statusLabel = new JLabel("Connecting...");
        statusLabel.setFont(SMALL_FONT);
        statusLabel.setForeground(TEXT_COLOR);

        JLabel versionLabel = new JLabel("v1.0");
        versionLabel.setFont(SMALL_FONT);
        versionLabel.setForeground(new Color(149, 165, 166));

        panel.add(statusLabel, BorderLayout.WEST);
        panel.add(versionLabel, BorderLayout.EAST);

        return panel;
    }

    private static JTextArea createChatTextArea() {
        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(DEFAULT_FONT);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        return textArea;
    }

    private static int getTabIndex(String title) {
        for (int i = 0; i < privateChatTabs.getTabCount(); i++) {
            Component tabComponent = privateChatTabs.getTabComponentAt(i);
            if (tabComponent instanceof JPanel) {
                JPanel panel = (JPanel) tabComponent;
                for (Component comp : panel.getComponents()) {
                    if (comp instanceof JLabel && ((JLabel) comp).getText().equals(title)) {
                        return i;
                    }
                }
            }
        }
        return -1;
    }

    private static void sendMessage() {
        String message = messageField.getText().trim();
        if (!message.isEmpty()) {
            int selectedTab = privateChatTabs.getSelectedIndex();
            String recipient = "Public";

            if (selectedTab > 0) {
                Component tabComponent = privateChatTabs.getTabComponentAt(selectedTab);
                if (tabComponent instanceof JPanel) {
                    JPanel panel = (JPanel) tabComponent;
                    for (Component comp : panel.getComponents()) {
                        if (comp instanceof JLabel) {
                            recipient = ((JLabel) comp).getText();
                            break;
                        }
                    }
                }
            }

            if (recipient.equals("Public")) {
                sendPublicMessage(message);
            } else {
                sendPrivateMessage(recipient, message);
            }
            messageField.setText("");
        }
    }

    private static void sendPublicMessage(String message) {
        if (out != null) {
            out.println("PUBLIC:" + message);
            appendToPublicChat("You: " + message);
        }
    }

    private static void sendPrivateMessage(String recipient, String message) {
        if (out != null) {
            out.println("PRIVATE:" + recipient + ":" + message);
            int tabIndex = getTabIndex(recipient);
            if (tabIndex != -1) {
                JScrollPane scrollPane = (JScrollPane) privateChatTabs.getComponentAt(tabIndex);
                JTextArea chatArea = (JTextArea) scrollPane.getViewport().getView();
                chatArea.append("You → " + recipient + ": " + message + "\n");
                chatArea.setCaretPosition(chatArea.getDocument().getLength());
            }
        }
    }

    private static void appendToPublicChat(String message) {
        publicChatArea.append(message + "\n");
        publicChatArea.setCaretPosition(publicChatArea.getDocument().getLength());
    }

    private static void openPrivateChatTab(String username) {
        if (getTabIndex(username) == -1) {
            JTextArea privateChatArea = createChatTextArea();
            JScrollPane privateChatScroll = new JScrollPane(privateChatArea);
            privateChatScroll.setBorder(BorderFactory.createEmptyBorder());

            JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
            tabPanel.setOpaque(false);

            JLabel tabLabel = new JLabel(username);
            tabLabel.setFont(DEFAULT_FONT);
            tabLabel.setIcon(new ImageIcon(createImageIcon(username.substring(0, 1).toUpperCase(), PRIMARY_COLOR, Color.WHITE)));

            JButton closeButton = new JButton("×");
            closeButton.setFont(new Font(closeButton.getFont().getName(), Font.BOLD, 14));
            closeButton.setPreferredSize(new Dimension(20, 20));
            closeButton.setFocusPainted(false);
            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);
            closeButton.addActionListener(e -> privateChatTabs.remove(getTabIndex(username)));

            tabPanel.add(tabLabel);
            tabPanel.add(closeButton);

            privateChatTabs.addTab(null, privateChatScroll);
            privateChatTabs.setTabComponentAt(privateChatTabs.getTabCount() - 1, tabPanel);
        }
    }

    private static Image createImageIcon(String text, Color background, Color foreground) {
        BufferedImage image = new BufferedImage(24, 24, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        g2d.setColor(background);
        g2d.fillOval(0, 0, 24, 24);
        
        g2d.setColor(foreground);
        g2d.setFont(new Font(DEFAULT_FONT.getName(), Font.BOLD, 12));
        FontMetrics fm = g2d.getFontMetrics();
        int textWidth = fm.stringWidth(text);
        int textHeight = fm.getHeight();
        
        g2d.drawString(text, (24 - textWidth) / 2, (24 - textHeight) / 2 + fm.getAscent());
        g2d.dispose();
        
        return image;
    }

    private static void connectToServer() {
        try {
            socket = new Socket(HOST, PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out.println(myUsername);

            statusLabel.setText("Connected as " + myUsername);
            statusLabel.setForeground(ACCENT_COLOR);

            new Thread(() -> {
                try {
                    String line;
                    while ((line = in.readLine()) != null) {
                        if (line.startsWith("USERLIST:")) {
                            updateUserList(Arrays.asList(line.substring(9).split(",")));
                        } else if (line.startsWith("PUBLIC:")) {
                            appendToPublicChat(line.substring(7));
                        } else if (line.startsWith("PRIVATE:")) {
                            String[] parts = line.substring(8).split(":", 2);
                            String sender = parts[0];
                            String message = parts[1];
                            SwingUtilities.invokeLater(() -> {
                                openPrivateChatTab(sender);
                                int tabIndex = getTabIndex(sender);
                                JScrollPane scrollPane = (JScrollPane) privateChatTabs.getComponentAt(tabIndex);
                                JTextArea chatArea = (JTextArea) scrollPane.getViewport().getView();
                                chatArea.append(sender + ": " + message + "\n");
                            });
                        }
                    }
                } catch (IOException e) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Disconnected: " + e.getMessage());
                        statusLabel.setForeground(new Color(231, 76, 60));
                    });
                }
            }).start();

        } catch (IOException e) {
            statusLabel.setText("Connection error: " + e.getMessage());
            statusLabel.setForeground(new Color(231, 76, 60));
        }
    }

    private static void updateUserList(List<String> userNames) {
        userListModel.clear();
        userNames.forEach(userListModel::addElement);
    }

    private static void disconnect() {
        try {
            if (out != null) out.close();
            if (in != null) in.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}