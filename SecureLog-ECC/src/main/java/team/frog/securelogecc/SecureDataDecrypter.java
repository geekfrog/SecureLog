package team.frog.securelogecc;

import team.frog.securelogecc.config.CryptoConfig;
import team.frog.securelogecc.core.EccCore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * SECURE_DATA 解密工具类。
 *
 * <p>用于离线排障或审计回溯：将日志中落盘的 SECURE_DATA（Base64）解出明文敏感数据 JSON。</p>
 *
 * <p>解密流程：
 * <ol>
 *   <li>Base64 解码 SECURE_DATA 并按固定结构解析 header</li>
 *   <li>使用 SM2 私钥解出 SM4 对称密钥（密钥封装部分）</li>
 *   <li>使用配置的 SM4 transformation（默认 GCM）解密敏感数据密文</li>
 * </ol>
 * </p>
 *
 * <p>SECURE_DATA v2（Base64 解码后的字节结构）：
 * <pre>
 * [version(1)][sm2KeyLen(4)][ivLen(1)][sm2EncryptedKey][iv][sm4Ciphertext]
 * </pre>
 * </p>
 */
public final class SecureDataDecrypter {
    private static final String EC_ALGORITHM = "EC";
    private static final String SM4_ALGORITHM = "SM4";
    private static final int SECURE_DATA_VERSION = 2;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final ThreadLocal<Cipher> SM4_DECRYPT_CIPHER = ThreadLocal.withInitial(() -> {
        try {
            CryptoConfig.ensureProviderAvailable();
            return Cipher.getInstance(CryptoConfig.getSm4CipherTransformation(), CryptoConfig.getCryptoProvider());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });

    private SecureDataDecrypter() {
    }

    public static String decryptSecureData(String secureData, PrivateKey privateKey) throws Exception {
        if (secureData == null || secureData.trim().isEmpty()) {
            throw new IllegalArgumentException("SECURE_DATA 不能为空");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("ECC 私钥不能为空");
        }

        byte[] combined = EccCore.base64Decode(secureData);
        if (combined.length < 1 + 4 + 1) {
            throw new Exception("加密数据长度不足，无法解析头部信息");
        }

        int offset = 0;
        int version = combined[offset++] & 0xFF;
        if (version != SECURE_DATA_VERSION) {
            throw new Exception("不支持的SECURE_DATA版本: " + version);
        }

        int keySize = ((combined[offset++] & 0xFF) << 24) |
                ((combined[offset++] & 0xFF) << 16) |
                ((combined[offset++] & 0xFF) << 8) |
                (combined[offset++] & 0xFF);
        int ivLen = combined[offset++] & 0xFF;

        if (keySize < 0 || combined.length < offset + keySize + ivLen) {
            throw new Exception("加密数据长度不足，SM2密文长度: " + keySize + ", IV长度: " + ivLen);
        }

        byte[] encryptedKey = new byte[keySize];
        System.arraycopy(combined, offset, encryptedKey, 0, keySize);
        offset += keySize;

        byte[] iv = new byte[ivLen];
        if (ivLen > 0) {
            System.arraycopy(combined, offset, iv, 0, ivLen);
        }
        offset += ivLen;

        byte[] encryptedData = new byte[combined.length - offset];
        System.arraycopy(combined, offset, encryptedData, 0, encryptedData.length);

        byte[] sm4KeyBytes = EccCore.decrypt(encryptedKey, privateKey);
        SecretKey sm4Key = new SecretKeySpec(sm4KeyBytes, SM4_ALGORITHM);

        try {
            Cipher cipher = SM4_DECRYPT_CIPHER.get();
            String transformation = CryptoConfig.getSm4CipherTransformation();
            if (transformation != null && transformation.toUpperCase().contains("/GCM/")) {
                cipher.init(Cipher.DECRYPT_MODE, sm4Key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            } else if (transformation != null && (transformation.toUpperCase().contains("/CBC/") || transformation.toUpperCase().contains("/CTR/") || transformation.toUpperCase().contains("/CFB/") || transformation.toUpperCase().contains("/OFB/"))) {
                cipher.init(Cipher.DECRYPT_MODE, sm4Key, new IvParameterSpec(iv));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, sm4Key);
            }
            byte[] plaintext = cipher.doFinal(encryptedData);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }

    public static String decryptSecureData(String secureData, String base64Pkcs8PrivateKey) throws Exception {
        return decryptSecureData(secureData, decodePrivateKey(base64Pkcs8PrivateKey));
    }

    public static PrivateKey decodePrivateKey(String base64Pkcs8PrivateKey) throws Exception {
        if (base64Pkcs8PrivateKey == null || base64Pkcs8PrivateKey.trim().isEmpty()) {
            throw new IllegalArgumentException("ECC 私钥不能为空");
        }

        CryptoConfig.ensureProviderAvailable();
        byte[] encoded = EccCore.base64Decode(base64Pkcs8PrivateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, CryptoConfig.getCryptoProvider());
        return keyFactory.generatePrivate(keySpec);
    }
}
