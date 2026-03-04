/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.manager;

import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.config.CryptoConfig;
import team.frog.securelogecc.core.EccCore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 密钥管理器类
 * 实现双轨密钥管理系统：
 * 1. 基于trace_id的会话密钥（用于业务日志）
 * 2. 系统级密钥（用于没有trace_id的系统日志，按配置间隔变化）
 */
public class KeyManager {

    /** SM4 对称密钥算法标识 */
    private static final String SM4_ALGORITHM = "SM4";
    /** SM4 密钥长度（bit） */
    private static final int SM4_KEY_SIZE = 128;

    /** 会话密钥缓存：trace_id -> 会话密钥信息 */
    private final Map<String, KeyInfo> sessionKeyCache;
    /** 会话密钥访问队列：维护创建顺序 */
    private final ConcurrentLinkedQueue<String> sessionAccessQueue;

    /** 系统密钥缓存：系统标识符 -> 系统密钥信息 */
    private final Map<String, KeyInfo> systemKeyCache;
    /** 系统密钥访问队列：维护创建顺序 */
    private final ConcurrentLinkedQueue<String> systemAccessQueue;

    /** 从配置文件加载的ECC公钥 */
    private final PublicKey configuredPublicKey;

    /** 配置参数 */
    private int sessionKeyCacheSize;
    private int systemKeyCacheSize;

    /** 清理标记，避免高并发下的重复清理 */
    private final AtomicBoolean isSessionCleaning = new AtomicBoolean(false);
    private final AtomicBoolean isSystemCleaning = new AtomicBoolean(false);

    /**
     * 使用默认配置创建KeyManager
     * 从配置文件中读取设置
     */
    public KeyManager() throws Exception {
        this(getConfigSessionKeyCacheSize(), getConfigSystemKeyCacheSize());
    }


    /**
     * 统一的配置读取模板方法 - 读取整数配置
     *
     * @param configKey    配置键
     * @param defaultValue 默认值
     * @return 配置值
     */
    private static int getIntConfig(String configKey, int defaultValue) {
        return ConfigManager.getInstance().getIntProperty(configKey, defaultValue);
    }

    /**
     * 统一的配置读取模板方法 - 读取浮点数配置
     *
     * @param configKey    配置键
     * @param defaultValue 默认值
     * @return 配置值
     */
    private static double getDoubleConfig(String configKey, double defaultValue) {
        return ConfigManager.getInstance().getDoubleProperty(configKey, defaultValue);
    }

    /**
     * 从配置文件读取会话密钥缓存大小
     *
     * @return 会话密钥缓存大小
     */
    private static int getConfigSessionKeyCacheSize() {
        return getIntConfig(ConfigConstants.SESSION_KEY_CACHE_SIZE, ConfigConstants.DEFAULT_SESSION_KEY_CACHE_SIZE);
    }

    /**
     * 从配置文件读取系统密钥缓存大小
     *
     * @return 系统密钥缓存大小
     */
    private static int getConfigSystemKeyCacheSize() {
        return getIntConfig(ConfigConstants.SYSTEM_KEY_CACHE_SIZE, ConfigConstants.DEFAULT_SYSTEM_KEY_CACHE_SIZE);
    }

    /**
     * 从配置文件读取会话密钥缓存缓冲百分比设置
     *
     * @return 会话密钥缓存缓冲百分比（0.0-1.0）
     */
    private static double getConfigSessionKeyCacheBufferPercentage() {
        double percentage = getDoubleConfig(ConfigConstants.SESSION_KEY_CACHE_BUFFER_PERCENTAGE, ConfigConstants.DEFAULT_SESSION_KEY_CACHE_BUFFER_PERCENTAGE);
        /** 确保百分比在合理范围内 */
        return Math.max(0.0, Math.min(1.0, percentage));
    }

    /**
     * 从配置文件读取系统密钥缓存缓冲百分比设置
     *
     * @return 系统密钥缓存缓冲百分比（0.0-1.0）
     */
    private static double getConfigSystemKeyCacheBufferPercentage() {
        double percentage = getDoubleConfig(ConfigConstants.SYSTEM_KEY_CACHE_BUFFER_PERCENTAGE, ConfigConstants.DEFAULT_SYSTEM_KEY_CACHE_BUFFER_PERCENTAGE);
        /** 确保百分比在合理范围内 */
        return Math.max(0.0, Math.min(1.0, percentage));
    }


    /**
     * 使用自定义配置创建KeyManager
     *
     * @param sessionKeyCacheSize 会话密钥缓存大小
     * @param systemKeyCacheSize  系统密钥缓存大小
     * @throws Exception 如果初始化失败
     */
    public KeyManager(int sessionKeyCacheSize, int systemKeyCacheSize) throws Exception {
        CryptoConfig.ensureProviderAvailable();
        /** 加载配置的ECC公钥 */
        String publicKeyStr = ConfigManager.getInstance().getProperty(ConfigConstants.ECC_PUBLIC_KEY, "");
        if (publicKeyStr.isEmpty()) {
            throw new Exception("必须配置ECC公钥: " + ConfigConstants.ECC_PUBLIC_KEY);
        }

        try {
            this.configuredPublicKey = EccCore.decodePublicKey(publicKeyStr);
        } catch (Exception e) {
            throw new Exception("ECC公钥解码失败: " + e.getMessage(), e);
        }

        this.sessionKeyCache = new ConcurrentHashMap<>();
        this.sessionAccessQueue = new ConcurrentLinkedQueue<>();
        this.systemKeyCache = new ConcurrentHashMap<>();
        this.systemAccessQueue = new ConcurrentLinkedQueue<>();
        this.sessionKeyCacheSize = sessionKeyCacheSize;
        this.systemKeyCacheSize = systemKeyCacheSize;
    }

    /**
     * 获取配置的ECC公钥
     *
     * @return 配置的ECC公钥
     */
    public PublicKey getConfiguredPublicKey() {
        return configuredPublicKey;
    }

    /**
     * 获取或创建系统级密钥信息
     * 能取到就返回，没有取到就生成。生成后数量超了就清理。
     *
     * @param systemTraceId 系统级标识符
     * @return KeyInfo对象
     * @throws Exception 如果密钥生成失败
     */
    public KeyInfo getOrCreateSystemKeyInfo(String systemTraceId) throws Exception {
        try {
            KeyInfo keyInfo = systemKeyCache.computeIfAbsent(systemTraceId, id -> {
                long currentTime = System.currentTimeMillis();
                try {
                    SecretKey sm4Key = generateSymmetricKey();
                    byte[] sm2EncryptedKey = EccCore.encrypt(sm4Key.getEncoded(), configuredPublicKey);
                    KeyInfo created = new KeyInfo(sm4Key, sm2EncryptedKey, currentTime);
                    systemAccessQueue.offer(id);
                    return created;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            if (systemKeyCache.size() >= systemKeyCacheSize) {
                evictOldestSystemKeys();
            }

            return keyInfo;
        } catch (RuntimeException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }


    /**
     * 公共的缓存清理逻辑
     *
     * @param cache            要清理的缓存
     * @param accessQueue      对应的访问队列
     * @param cacheSize        缓存大小限制
     * @param bufferPercentage 缓冲百分比
     */
    private void evictOldestKeys(Map<String, KeyInfo> cache, ConcurrentLinkedQueue<String> accessQueue,
                                 int cacheSize, double bufferPercentage) {
        /** 计算清理目标 */
        /** 目标大小 = 总缓存大小 × (1 - 缓冲百分比) */
        /** 例如：100 × (1 - 0.3) = 70，留出30个空位 */
        int targetSize = (int) (cacheSize * (1 - bufferPercentage));
        /** 确保不小于0 */
        targetSize = Math.max(0, targetSize);

        /** 如果缓存超过目标大小，从队列头部移除最旧的密钥 */
        while (cache.size() > targetSize && !accessQueue.isEmpty()) {
            String oldest = accessQueue.poll();
            if (oldest != null) {
                cache.remove(oldest);
            }
        }
    }

    /**
     * 当缓存达到上限时，清除最旧的系统密钥
     * 策略：
     * 缓存超过上限后按创建顺序淘汰，直到达到目标大小（留出缓冲区，减少频繁清理）
     */
    private void evictOldestSystemKeys() {
        if (!isSystemCleaning.compareAndSet(false, true)) {
            return;
        }

        try {
            evictOldestKeys(systemKeyCache, systemAccessQueue, systemKeyCacheSize,
                    getConfigSystemKeyCacheBufferPercentage());
        } finally {
            isSystemCleaning.set(false);
        }
    }

    /**
     * 获取或创建会话级密钥信息
     * 能取到就返回，没有取到就生成。生成后数量超了就清理。
     *
     * @param traceId 会话ID
     * @return KeyInfo对象
     * @throws Exception 如果密钥生成失败
     */
    public KeyInfo getOrCreateSessionKeyInfo(String traceId) throws Exception {
        if (traceId == null || traceId.isEmpty()) {
            throw new IllegalArgumentException("traceId不能为空");
        }

        try {
            KeyInfo keyInfo = sessionKeyCache.computeIfAbsent(traceId, id -> {
                long currentTime = System.currentTimeMillis();
                try {
                    SecretKey sm4Key = generateSymmetricKey();
                    byte[] sm2EncryptedKey = EccCore.encrypt(sm4Key.getEncoded(), configuredPublicKey);
                    KeyInfo created = new KeyInfo(sm4Key, sm2EncryptedKey, currentTime);
                    sessionAccessQueue.offer(id);
                    return created;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            if (sessionKeyCache.size() >= sessionKeyCacheSize) {
                evictOldestSessionKeys();
            }

            return keyInfo;
        } catch (RuntimeException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }


    /**
     * 当缓存达到上限时，清除最旧的会话密钥
     * 策略：
     * 缓存超过上限后按创建顺序淘汰，直到达到目标大小（留出缓冲区，减少频繁清理）
     */
    private void evictOldestSessionKeys() {
        if (!isSessionCleaning.compareAndSet(false, true)) {
            return;
        }

        try {
            evictOldestKeys(sessionKeyCache, sessionAccessQueue, sessionKeyCacheSize,
                    getConfigSessionKeyCacheBufferPercentage());
        } finally {
            isSessionCleaning.set(false);
        }
    }


    /**
     * 生成对称密钥（SM4）
     *
     * @return 生成的对称密钥
     * @throws Exception 如果密钥生成失败
     */
    private SecretKey generateSymmetricKey() throws Exception {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(SM4_ALGORITHM, CryptoConfig.getCryptoProvider());
            keyGenerator.init(SM4_KEY_SIZE, new SecureRandom());
            return keyGenerator.generateKey();
        } catch (Exception e) {
            throw new Exception("对称密钥生成失败: " + e.getMessage(), e);
        }
    }


    /**
     * 加密对称密钥
     * 使用配置的ECC公钥加密对称密钥
     *
     * @param symmetricKey 要加密的对称密钥
     * @return 加密后的对称密钥字节数组
     * @throws Exception 如果加密失败
     */
    public byte[] encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
        if (configuredPublicKey == null) {
            throw new Exception("ECC公钥未配置");
        }

        return EccCore.encrypt(symmetricKey.getEncoded(), configuredPublicKey);
    }

    /**
     * 解密对称密钥
     * 注意：由于我们只使用配置的公钥，解密需要使用对应的私钥
     * 私钥应该由调用方提供，因为我们不存储私钥
     *
     * @param encryptedSymmetricKey 加密的对称密钥字节数组
     * @param privateKey            ECC私钥
     * @return 解密后的对称密钥
     * @throws Exception 如果解密失败
     */
    public SecretKey decryptSymmetricKey(byte[] encryptedSymmetricKey, java.security.PrivateKey privateKey) throws Exception {
        byte[] keyBytes = EccCore.decrypt(encryptedSymmetricKey, privateKey);
        return new SecretKeySpec(keyBytes, SM4_ALGORITHM);
    }

    /**
     * 清除会话密钥缓存
     */
    public void clearSessionKeyCache() {
        evictOldestKeys(
                sessionKeyCache,
                sessionAccessQueue,
                sessionKeyCacheSize,
                getConfigSessionKeyCacheBufferPercentage()
        );
        sessionAccessQueue.removeIf(entry -> !sessionKeyCache.containsKey(entry));
    }

    /**
     * 清除系统密钥缓存
     */
    public void clearSystemKeyCache() {
        evictOldestKeys(
                systemKeyCache,
                systemAccessQueue,
                systemKeyCacheSize,
                getConfigSystemKeyCacheBufferPercentage()
        );
        systemAccessQueue.removeIf(entry -> !systemKeyCache.containsKey(entry));
    }

    /**
     * 清除所有缓存
     */
    public void clearAllCaches() {
        clearSessionKeyCache();
        clearSystemKeyCache();
    }


    /**
     * 获取会话密钥缓存大小
     *
     * @return 会话密钥缓存大小
     */
    public int getSessionKeyCacheSize() {
        return sessionKeyCacheSize;
    }

    /**
     * 设置会话密钥缓存大小
     *
     * @param sessionKeyCacheSize 会话密钥缓存大小
     */
    public void setSessionKeyCacheSize(int sessionKeyCacheSize) {
        if (sessionKeyCacheSize <= 0) {
            throw new IllegalArgumentException("会话密钥缓存大小必须为正数");
        }
        this.sessionKeyCacheSize = sessionKeyCacheSize;
    }

    /**
     * 获取系统密钥缓存大小
     *
     * @return 系统密钥缓存大小
     */
    public int getSystemKeyCacheSize() {
        return systemKeyCacheSize;
    }

    /**
     * 设置系统密钥缓存大小
     *
     * @param systemKeyCacheSize 系统密钥缓存大小
     */
    public void setSystemKeyCacheSize(int systemKeyCacheSize) {
        if (systemKeyCacheSize <= 0) {
            throw new IllegalArgumentException("系统密钥缓存大小必须为正数");
        }
        this.systemKeyCacheSize = systemKeyCacheSize;
    }


    /**
     * 密钥信息封装类
     * 封装SM4密钥、SM2密文和创建时间
     */
    public static class KeyInfo {
        /** SM4对称密钥 */
        private final SecretKey sm4Key;
        /** SM2加密的SM4密钥密文 */
        private final byte[] sm2EncryptedKey;
        /** 创建时间戳 */
        private final long creationTime;

        /**
         * 创建密钥信息。
         *
         * @param sm4Key SM4 对称密钥
         * @param sm2EncryptedKey SM2 加密的 SM4 密钥密文
         * @param creationTime 创建时间戳
         */
        public KeyInfo(SecretKey sm4Key, byte[] sm2EncryptedKey, long creationTime) {
            this.sm4Key = sm4Key;
            this.sm2EncryptedKey = sm2EncryptedKey;
            this.creationTime = creationTime;
        }

        /**
         * 获取 SM4 对称密钥。
         *
         * @return SM4 密钥
         */
        public SecretKey getSm4Key() {
            return sm4Key;
        }

        /**
         * 获取 SM2 加密的 SM4 密钥密文。
         *
         * @return SM2 密钥密文
         */
        public byte[] getSm2EncryptedKey() {
            return sm2EncryptedKey;
        }

        /**
         * 获取创建时间戳。
         *
         * @return 创建时间戳
         */
        public long getCreationTime() {
            return creationTime;
        }
    }
}
