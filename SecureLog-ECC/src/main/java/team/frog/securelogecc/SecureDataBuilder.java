/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc;

import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.config.CryptoConfig;
import team.frog.securelogecc.core.EccCore;
import team.frog.securelogecc.manager.ConfigManager;
import team.frog.securelogecc.manager.KeyManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * SECURE_DATA 构建器。
 *
 * <p>职责：
 * <ul>
 *   <li>通过 {@link KeyManager} 获取或生成 SM4 会话密钥/系统密钥</li>
 *   <li>使用 SM2 公钥加密 SM4 密钥（形成密钥密文）</li>
 *   <li>使用配置的 SM4 算法（默认 GCM）加密敏感数据 JSON</li>
 *   <li>按固定二进制结构拼装并 Base64 输出 SECURE_DATA</li>
 * </ul>
 * </p>
 *
 * <p>SECURE_DATA（Base64 解码后的字节结构）：
 * <pre>
 * [version(1)][sm2KeyLen(4)][ivLen(1)][sm2EncryptedKey][iv][sm4Ciphertext]
 * </pre>
 * </p>
 *
 * <p>性能：
 * <ul>
 *   <li>SM4 Cipher 使用 ThreadLocal 缓存，减少对象创建与 provider 查找开销</li>
 *   <li>IV/nonce 由线程本地 {@link SecureRandom} 生成</li>
 * </ul>
 * </p>
 */
public class SecureDataBuilder {

    /** 密钥管理器（负责会话密钥/系统密钥缓存） */
    private final KeyManager keyManager;
    /** SECURE_DATA 版本号（用于兼容解析） */
    private static final byte SECURE_DATA_VERSION = 2;
    /** GCM 模式 IV 长度（字节） */
    private static final int GCM_IV_LENGTH_BYTES = 12;
    /** GCM 模式认证标签长度（比特） */
    private static final int GCM_TAG_LENGTH_BITS = 128;
    /** 线程本地随机数生成器 */
    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);
    /** 线程本地 SM4 加密 Cipher */
    private static final ThreadLocal<Cipher> SM4_ENCRYPT_CIPHER = ThreadLocal.withInitial(() -> {
        try {
            CryptoConfig.ensureProviderAvailable();
            return Cipher.getInstance(CryptoConfig.getSm4CipherTransformation(), CryptoConfig.getCryptoProvider());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });
    /** 线程本地 SM4 解密 Cipher */
    private static final ThreadLocal<Cipher> SM4_DECRYPT_CIPHER = ThreadLocal.withInitial(() -> {
        try {
            CryptoConfig.ensureProviderAvailable();
            return Cipher.getInstance(CryptoConfig.getSm4CipherTransformation(), CryptoConfig.getCryptoProvider());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    });

    /**
     * 使用默认KeyManager创建SecureDataBuilder
     *
     * @throws Exception 如果初始化失败
     */
    public SecureDataBuilder() throws Exception {
        this.keyManager = new KeyManager();
    }

    /**
     * 使用自定义KeyManager创建SecureDataBuilder
     *
     * @param keyManager KeyManager实例
     */
    public SecureDataBuilder(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * 为带有trace_id的业务日志构建SECURE_DATA
     *
     * @param sensitiveData 要加密的敏感数据
     * @param traceId       用于会话密钥的跟踪ID
     * @return SECURE_DATA作为Base64字符串
     * @throws Exception 如果加密失败
     */
    public String buildSecureDataForBusinessLog(String sensitiveData, String traceId) throws Exception {
        /** 一次性获取KeyInfo对象，避免原子性问题 */
        KeyManager.KeyInfo keyInfo = keyManager.getOrCreateSessionKeyInfo(traceId);

        /** 使用同一个KeyInfo对象获取SM4密钥和SM2密文 */
        SecretKey sessionKey = keyInfo.getSm4Key();
        byte[] encryptedKey = keyInfo.getSm2EncryptedKey();

        /** 使用会话密钥加密敏感数据 */
        Sm4EncryptedPayload encryptedPayload = encryptWithSymmetricKey(sensitiveData.getBytes("UTF-8"), sessionKey);

        return buildSecureData(encryptedKey, encryptedPayload.iv, encryptedPayload.ciphertext);
    }

    /**
     * 为没有trace_id的系统日志构建SECURE_DATA
     * 使用系统级标识符（按配置间隔变化）
     *
     * @param sensitiveData 要加密的敏感数据
     * @return SECURE_DATA作为Base64字符串
     * @throws Exception 如果加密失败
     */
    public String buildSecureDataForSystemLog(String sensitiveData) throws Exception {
        /** 生成系统级标识符（按配置间隔变化） */
        String systemTraceId = generateSystemTraceId();

        /** 使用系统级标识符获取KeyInfo对象，系统级使用独立的缓存 */
        KeyManager.KeyInfo keyInfo = keyManager.getOrCreateSystemKeyInfo(systemTraceId);

        /** 使用同一个KeyInfo对象获取SM4密钥和SM2密文 */
        SecretKey systemKey = keyInfo.getSm4Key();
        byte[] encryptedKey = keyInfo.getSm2EncryptedKey();

        /** 使用系统级密钥加密敏感数据 */
        Sm4EncryptedPayload encryptedPayload = encryptWithSymmetricKey(sensitiveData.getBytes("UTF-8"), systemKey);

        return buildSecureData(encryptedKey, encryptedPayload.iv, encryptedPayload.ciphertext);
    }

    /**
     * 生成系统级标识符
     * 系统标识符按固定时间间隔变化，每N分钟变化一次
     * 格式：system_时间间隔编号，其中时间间隔编号 = 当前时间戳 / (N分钟对应的毫秒数)
     * 例如：N=15分钟，则0-14分钟为system_0，15-29分钟为system_1，以此类推
     *
     * @return 系统级标识符
     */
    private String generateSystemTraceId() {
        long currentTime = System.currentTimeMillis();
        /** 从配置读取系统标识符变化间隔（分钟） */
        int systemIdChangeIntervalMinutes = ConfigManager.getInstance().getIntProperty(
                ConfigConstants.SYSTEM_ID_CHANGE_INTERVAL_MINUTES,
                ConfigConstants.DEFAULT_SYSTEM_ID_CHANGE_INTERVAL_MINUTES
        );
        /** 计算当前时间属于第几个时间间隔 */
        long intervalId = currentTime / (systemIdChangeIntervalMinutes * ConfigConstants.MILLIS_PER_MINUTE);
        return "system_" + intervalId;
    }

    /**
     * 构建SECURE_DATA字段
     *
     * @param encryptedKey  SM2加密的对称密钥
     * @param iv            SM4的IV/nonce
     * @param encryptedData 密钥加密的敏感数据
     * @return SECURE_DATA作为Base64字符串
     */
    private String buildSecureData(byte[] encryptedKey, byte[] iv, byte[] encryptedData) {
        if (encryptedKey == null || iv == null || encryptedData == null) {
            throw new IllegalArgumentException("SECURE_DATA构建参数不能为空");
        }

        /** 版本(1) + keyLen(4) + ivLen(1) + sm2Key + iv + sm4Ciphertext */
        byte[] keyLengthBytes = new byte[4];
        keyLengthBytes[0] = (byte) ((encryptedKey.length >> 24) & 0xFF);
        keyLengthBytes[1] = (byte) ((encryptedKey.length >> 16) & 0xFF);
        keyLengthBytes[2] = (byte) ((encryptedKey.length >> 8) & 0xFF);
        keyLengthBytes[3] = (byte) (encryptedKey.length & 0xFF);

        byte[] combined = new byte[1 + 4 + 1 + encryptedKey.length + iv.length + encryptedData.length];
        int offset = 0;
        combined[offset++] = SECURE_DATA_VERSION;
        System.arraycopy(keyLengthBytes, 0, combined, offset, 4);
        offset += 4;
        combined[offset++] = (byte) (iv.length & 0xFF);
        System.arraycopy(encryptedKey, 0, combined, offset, encryptedKey.length);
        offset += encryptedKey.length;
        System.arraycopy(iv, 0, combined, offset, iv.length);
        offset += iv.length;
        System.arraycopy(encryptedData, 0, combined, offset, encryptedData.length);

        /** Base64编码 */
        return EccCore.base64Encode(combined);
    }

    /**
     * 使用对称密钥（SM4）加密数据
     *
     * @param data         要加密的数据
     * @param symmetricKey 对称密钥
     * @return 加密的IV和密文
     * @throws Exception 如果加密失败
     */
    private Sm4EncryptedPayload encryptWithSymmetricKey(byte[] data, SecretKey symmetricKey) throws Exception {
        try {
            Cipher cipher = SM4_ENCRYPT_CIPHER.get();
            String transformation = CryptoConfig.getSm4CipherTransformation();
            if (isGcm(transformation)) {
                byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
                SECURE_RANDOM.get().nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
                return new Sm4EncryptedPayload(iv, cipher.doFinal(data));
            }
            if (usesIv(transformation)) {
                byte[] iv = new byte[16];
                SECURE_RANDOM.get().nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
                return new Sm4EncryptedPayload(iv, cipher.doFinal(data));
            }
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            return new Sm4EncryptedPayload(new byte[0], cipher.doFinal(data));
        } catch (RuntimeException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }

    private static final class Sm4EncryptedPayload {
        private final byte[] iv;
        private final byte[] ciphertext;

        private Sm4EncryptedPayload(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    private boolean isGcm(String transformation) {
        return transformation != null && transformation.toUpperCase().contains("/GCM/");
    }

    private boolean usesIv(String transformation) {
        if (transformation == null) {
            return false;
        }
        String t = transformation.toUpperCase();
        return t.contains("/CBC/") || t.contains("/CTR/") || t.contains("/CFB/") || t.contains("/OFB/");
    }

    /**
     * 解析SECURE_DATA字段
     *
     * @param secureData SECURE_DATA作为Base64字符串
     * @return 包含加密密钥和加密数据的ParsedSecureData对象
     * @throws Exception 如果解析失败
     */
    public ParsedSecureData parseSecureData(String secureData) throws Exception {
        /** 解码Base64 */
        byte[] combined = EccCore.base64Decode(secureData);

        if (combined.length < 1 + 4 + 1) {
            throw new Exception("加密数据长度不足，无法解析头部信息");
        }

        int offset = 0;
        int version = combined[offset++] & 0xFF;
        if (version != (SECURE_DATA_VERSION & 0xFF)) {
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

        return new ParsedSecureData(encryptedKey, iv, encryptedData);
    }

    /**
     * 解析的SECURE_DATA容器
     */
    public static class ParsedSecureData {
        private final byte[] encryptedKey;
        private final byte[] iv;
        private final byte[] encryptedData;

        /**
         * 创建解析后的 SECURE_DATA 容器。
         *
         * @param encryptedKey SM2 加密的对称密钥
         * @param iv           SM4 IV/nonce
         * @param encryptedData SM4 加密的敏感数据
         */
        public ParsedSecureData(byte[] encryptedKey, byte[] iv, byte[] encryptedData) {
            this.encryptedKey = encryptedKey;
            this.iv = iv;
            this.encryptedData = encryptedData;
        }

        /**
         * 获取 SM2 加密的对称密钥。
         *
         * @return SM2 密钥密文
         */
        public byte[] getEncryptedKey() {
            return encryptedKey;
        }

        /**
         * 获取 SM4 的 IV/nonce。
         *
         * @return IV/nonce 字节数组
         */
        public byte[] getIv() {
            return iv;
        }

        /**
         * 获取 SM4 加密的敏感数据。
         *
         * @return 密文数据
         */
        public byte[] getEncryptedData() {
            return encryptedData;
        }
    }


    /**
     * 解密SECURE_DATA
     *
     * @param secureData SECURE_DATA作为Base64字符串
     * @param privateKey ECC私钥，用于解密对称密钥
     * @return 解密后的敏感数据
     * @throws Exception 如果解密失败
     */
    public String decryptSecureData(String secureData, java.security.PrivateKey privateKey) throws Exception {
        /** 解析SECURE_DATA */
        ParsedSecureData parsed = parseSecureData(secureData);

        /** 解密对称密钥 */
        SecretKey symmetricKey = keyManager.decryptSymmetricKey(parsed.getEncryptedKey(), privateKey);

        /** 解密密文数据 */
        return decryptWithSymmetricKey(parsed.getEncryptedData(), symmetricKey, parsed.getIv());
    }

    /**
     * 使用对称密钥（SM4）解密数据
     *
     * @param encryptedData 加密的数据
     * @param symmetricKey  对称密钥
     * @param iv            SM4的IV/nonce
     * @return 解密的数据
     * @throws Exception 如果解密失败
     */
    private String decryptWithSymmetricKey(byte[] encryptedData, SecretKey symmetricKey, byte[] iv) throws Exception {
        try {
            Cipher cipher = SM4_DECRYPT_CIPHER.get();
            String transformation = CryptoConfig.getSm4CipherTransformation();
            if (isGcm(transformation)) {
                cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            } else if (usesIv(transformation)) {
                cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            }
            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData, "UTF-8");
        } catch (RuntimeException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }
}
