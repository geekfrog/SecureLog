/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.core;

import team.frog.securelogecc.config.CryptoConfig;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * 密码学基础工具类。
 *
 * <p>封装本组件对 JCE 的最小依赖：
 * <ul>
 *   <li>SM2：用于加/解密 SM4 对称密钥（混合加密的“密钥封装”部分）</li>
 *   <li>Base64：用于 SECURE_DATA 的编码/解码</li>
 *   <li>公钥解码：从 X509 Base64 解出 {@link PublicKey}</li>
 * </ul>
 * </p>
 *
 * <p>所有 JCE 操作通过 {@link CryptoConfig} 解析并加载 Provider。</p>
 */
public class EccCore {

    private static final String EC_ALGORITHM = "EC";

    static {
        CryptoConfig.ensureProviderAvailable();
    }

    /**
     * 使用SM2加密数据
     * 真正的SM2加密实现
     *
     * @param data      要加密的明文数据（这里是SM4对称密钥的字节数组）
     * @param publicKey SM2公钥
     * @return 加密后的数据字节数组
     * @throws Exception 如果加密失败
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        try {
            // 使用真正的SM2加密算法
            Cipher cipher = Cipher.getInstance(CryptoConfig.getSm2CipherTransformation(), CryptoConfig.getCryptoProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new Exception("SM2加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 使用SM2解密数据
     * 真正的SM2解密实现
     *
     * @param encryptedData 加密的数据字节数组（SM2加密的SM4密钥）
     * @param privateKey    SM2私钥
     * @return 解密后的明文字节数组
     * @throws Exception 如果解密失败
     */
    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        try {
            // 使用真正的SM2解密算法
            Cipher cipher = Cipher.getInstance(CryptoConfig.getSm2CipherTransformation(), CryptoConfig.getCryptoProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new Exception("SM2解密失败: " + e.getMessage(), e);
        }
    }

    /**
     * Base64编码字节
     *
     * @param bytes 要编码的字节
     * @return Base64编码的字符串
     */
    public static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Base64解码字符串
     *
     * @param base64String Base64编码的字符串
     * @return 解码的字节
     */
    public static byte[] base64Decode(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    /**
     * 从Base64字符串解码公钥
     *
     * @param base64PublicKey Base64编码的公钥字符串
     * @return 解码后的公钥
     * @throws Exception 如果解码失败
     */
    public static PublicKey decodePublicKey(String base64PublicKey) throws Exception {
        try {
            byte[] encodedPublicKey = base64Decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, CryptoConfig.getCryptoProvider());
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new Exception("公钥解码失败: " + e.getMessage(), e);
        }
    }

    /**
     * 计算公钥指纹。
     *
     * @param base64PublicKey Base64 公钥
     * @return 公钥指纹（Base64）
     */
    public static String publicKeyFingerprint(String base64PublicKey) {
        if (base64PublicKey == null || base64PublicKey.trim().isEmpty()) {
            return null;
        }
        try {
            byte[] decoded = base64Decode(base64PublicKey.trim());
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(decoded);
            byte[] head = Arrays.copyOf(digest, Math.min(20, digest.length));
            return base64Encode(head);
        } catch (Exception e) {
            return null;
        }
    }
}
