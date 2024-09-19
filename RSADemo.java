import javax.crypto.Cipher;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class RSADemo {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            // 生成RSA密钥对
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 保存公钥和私钥
            saveKeyToFile("publicKey.pem", publicKey);
            saveKeyToFile("privateKey.pem", privateKey);

            // 用户交互：获取数据
            System.out.print("请输入需要加密的数据：");
            String originalData = scanner.nextLine();

            // 加密数据
            String encryptedData = encryptData(publicKey, originalData);
            System.out.println("加密后的数据（Base64编码）：" + encryptedData);

            // 用户交互：获取解密数据
            System.out.print("请输入需要解密的加密数据（Base64编码）：");
            String encryptedDataForDecryption = scanner.nextLine();

            // 解密数据
            String decryptedData = decryptData(privateKey, encryptedDataForDecryption);
            System.out.println("解密后的数据：" + decryptedData);

            // 创建数字签名
            String digitalSignature = generateDigitalSignature(privateKey, originalData);
            System.out.println("数字签名（Base64编码）：" + digitalSignature);

            // 验证数字签名
            boolean isSignatureValid = verifyDigitalSignature(publicKey, originalData, digitalSignature);
            System.out.println("数字签名验证结果：" + (isSignatureValid ? "有效" : "无效"));

        } catch (Exception e) {
            System.err.println("发生错误：" + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    // 生成RSA密钥对
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // 保存密钥到文件
    private static void saveKeyToFile(String fileName, Key key) throws IOException {
        String keyString = Base64.getEncoder().encodeToString(key.getEncoded());
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(keyString);
        }
    }

    // 从文件加载密钥
    private static Key loadKeyFromFile(String fileName, boolean isPublicKey) throws Exception {
        String keyString = new String(Files.readAllBytes(Paths.get(fileName)));
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key key = isPublicKey
                ? keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes))
                : keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        return key;
    }

    // 加密数据
    private static String encryptData(PublicKey publicKey, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密数据
    private static String decryptData(PrivateKey privateKey, String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    // 生成数字签名
    private static String generateDigitalSignature(PrivateKey privateKey, String data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 验证数字签名
    private static boolean verifyDigitalSignature(PublicKey publicKey, String data, String signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }
}