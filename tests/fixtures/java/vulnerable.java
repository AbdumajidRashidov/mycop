import java.sql.*;
import java.util.Random;
import java.io.*;
import java.security.MessageDigest;

class vulnerable {

    // SQL Injection - string concatenation
    public void getUser(Connection conn, String id) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
    }

    // Command Injection
    public void runCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    // Hardcoded secret
    public static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";

    // Insecure random
    public int generateToken() {
        Random random = new Random();
        return random.nextInt(999999);
    }

    // Path traversal
    public void readFile(String filename) throws Exception {
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        fis.read();
        fis.close();
    }

    // XXE vulnerable
    public void parseXml(InputStream is) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(is);
    }

    // XSS - writing user input to output
    public void handleRequest(InputStream input, OutputStream output) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        String name = reader.readLine();
        PrintWriter writer = new PrintWriter(output);
        writer.println("<h1>Hello " + name + "</h1>");
    }

    // Insecure deserialization
    public Object deserialize(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }

    // Weak hash MD5
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // ECB mode
    public void encrypt(byte[] data) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, (java.security.Key) null);
    }

    // Empty catch
    public void riskyOperation() {
        try {
            dangerousMethod();
        } catch (Exception e) {
        }
    }

    // Error info leak
    public void handleError(Exception e) throws Exception {
        e.printStackTrace();
    }

    private void dangerousMethod() throws Exception {
        throw new Exception("error");
    }
}
