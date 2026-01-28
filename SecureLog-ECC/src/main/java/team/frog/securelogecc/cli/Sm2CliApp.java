package team.frog.securelogecc.cli;

import team.frog.securelogecc.SecureDataDecrypter;
import team.frog.securelogecc.config.CryptoConfig;
import team.frog.securelogecc.core.EccCore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Sm2CliApp {
    private static final String DECRYPT_OUTPUT_FILE = "sm2_decrypt_output.txt";

    public void runCli() throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        while (true) {
            String choice = prompt(reader, "请选择操作：1.生成SM2密钥对  2.解密  (输入exit/quit退出)");
            if (choice == null) {
                return;
            }
            String normalized = choice.trim();
            if (isExit(normalized)) {
                System.out.println("程序已关闭。");
                return;
            }
            if ("1".equals(normalized)) {
                handleGenerate(reader);
                continue;
            }
            if ("2".equals(normalized)) {
                handleDecrypt(reader);
                continue;
            }
            System.out.println("输入无效，请输入1或2，或输入exit/quit退出。");
        }
    }

    private void handleGenerate(BufferedReader reader) throws Exception {
        KeyPair keyPair = generateSm2KeyPair();
        String publicKeyBase64 = EccCore.base64Encode(keyPair.getPublic().getEncoded());
        String privateKeyBase64 = EccCore.base64Encode(keyPair.getPrivate().getEncoded());

        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        Path publicKeyPath = Paths.get("sm2_public_key_" + timestamp + ".txt");
        Path privateKeyPath = Paths.get("sm2_private_key_" + timestamp + ".txt");

        writeString(publicKeyPath, publicKeyBase64);
        writeString(privateKeyPath, privateKeyBase64);

        System.out.println("公钥（Base64）:");
        System.out.println(publicKeyBase64);
        System.out.println("私钥（Base64）:");
        System.out.println(privateKeyBase64);
        System.out.println("密钥已保存到文件：");
        System.out.println(publicKeyPath.toAbsolutePath());
        System.out.println(privateKeyPath.toAbsolutePath());
        System.out.println("请妥善保存，避免泄露。");
    }

    private void handleDecrypt(BufferedReader reader) throws Exception {
        PrivateKey privateKey = null;
        while (privateKey == null) {
            String privateKeyInput = prompt(reader, "请输入用于解密的私钥（Base64格式）：");
            if (privateKeyInput == null) {
                return;
            }
            String trimmed = privateKeyInput.trim();
            if (trimmed.isEmpty()) {
                System.out.println("私钥不能为空，请重新输入。");
                continue;
            }
            try {
                privateKey = SecureDataDecrypter.decodePrivateKey(trimmed);
            } catch (Exception e) {
                System.out.println("私钥格式无效，请输入Base64格式的私钥。");
            }
        }

        while (true) {
            String secureDataInput = prompt(reader, "请输入要解密的SECURE_DATA（Base64格式）：");
            if (secureDataInput == null) {
                return;
            }
            String secureDataBase64 = secureDataInput.trim();
            if (secureDataBase64.isEmpty()) {
                System.out.println("SECURE_DATA不能为空，请重新输入。");
            } else {
                decryptOnce(secureDataBase64, privateKey);
            }

            String decision = prompt(reader, "是否继续解密？(输入‘c’继续，其他任意键退出)");
            if (decision == null) {
                return;
            }
            if (!"c".equalsIgnoreCase(decision.trim())) {
                return;
            }
        }
    }

    private void decryptOnce(String secureDataBase64, PrivateKey privateKey) {
        try {
            String plaintext = SecureDataDecrypter.decryptSecureData(secureDataBase64, privateKey);
            System.out.println("解密后的明文：" + plaintext);
            appendLine(Paths.get(DECRYPT_OUTPUT_FILE), plaintext);
            System.out.println("数据已追加到：" + Paths.get(DECRYPT_OUTPUT_FILE).toAbsolutePath());
            System.out.println();
        } catch (IllegalArgumentException e) {
            System.out.println("SECURE_DATA格式无效，请输入Base64格式的SECURE_DATA。");
        } catch (Exception e) {
            System.out.println("解密失败，请检查私钥和SECURE_DATA是否正确。");
        }
    }

    private KeyPair generateSm2KeyPair() throws Exception {
        CryptoConfig.ensureProviderAvailable();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", CryptoConfig.getCryptoProvider());
        ECGenParameterSpec spec = new ECGenParameterSpec(CryptoConfig.getSm2CurveName());
        keyPairGenerator.initialize(spec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private String prompt(BufferedReader reader, String message) throws IOException {
        System.out.println(message);
        return reader.readLine();
    }

    private void writeString(Path path, String content) throws IOException {
        Files.write(path, content.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
    }

    private void appendLine(Path path, String content) throws IOException {
        Files.write(path, (content + System.lineSeparator() + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }

    private boolean isExit(String input) {
        return "exit".equalsIgnoreCase(input) || "quit".equalsIgnoreCase(input);
    }
}
