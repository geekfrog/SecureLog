package team.frog.securelogecc.manager;

import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.core.EccCore;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * 配置管理器类
 * 管理SecureLog ECC组件的配置
 */
public class ConfigManager {

    private static final String DEFAULT_CONFIG_FILE = "securelog-ecc.properties";
    private static final ConfigManager INSTANCE = new ConfigManager();

    private Properties properties;
    private volatile boolean initialized = false;
    private volatile String cachedPublicKeyBase64;
    private volatile String cachedPublicKeyFingerprint;

    private ConfigManager() {
        this.properties = new Properties();
    }

    /**
     * 获取单例实例
     *
     * @return ConfigManager实例
     */
    public static ConfigManager getInstance() {
        return INSTANCE;
    }

    /**
     * 使用默认配置文件初始化
     *
     * @throws Exception 如果初始化失败
     */
    public void initialize() throws Exception {
        initialize(DEFAULT_CONFIG_FILE);
    }

    /**
     * 使用自定义配置文件初始化
     *
     * @param configFile 配置文件路径
     * @throws Exception 如果初始化失败
     */
    public synchronized void initialize(String configFile) throws Exception {
        // 保存当前设置的属性
        Properties currentProperties = new Properties();
        currentProperties.putAll(properties);

        // 清除并重新加载
        properties.clear();

        // 尝试从文件系统加载
        try {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(new InputStreamReader(fis, StandardCharsets.UTF_8));
                // 恢复之前设置的属性（这些属性优先级更高）
                properties.putAll(currentProperties);
                initialized = true;
                cachedPublicKeyBase64 = null;
                cachedPublicKeyFingerprint = null;
                return;
            }
        } catch (FileNotFoundException e) {
            // 文件不存在，继续使用默认值
        }

        // 尝试从类路径加载
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(configFile)) {
            if (is != null) {
                properties.load(new InputStreamReader(is, StandardCharsets.UTF_8));
                // 恢复之前设置的属性（这些属性优先级更高）
                properties.putAll(currentProperties);
                initialized = true;
                cachedPublicKeyBase64 = null;
                cachedPublicKeyFingerprint = null;
                return;
            }
        }

        // 如果没有找到配置文件，使用默认值
        loadDefaults();
        // 恢复之前设置的属性（这些属性优先级更高）
        properties.putAll(currentProperties);
        initialized = true;
        cachedPublicKeyBase64 = null;
        cachedPublicKeyFingerprint = null;
    }

    /**
     * 加载默认配置
     */
    private void loadDefaults() {
        properties.setProperty(ConfigConstants.SYSTEM_ID_CHANGE_INTERVAL_MINUTES, String.valueOf(ConfigConstants.DEFAULT_SYSTEM_ID_CHANGE_INTERVAL_MINUTES));
        properties.setProperty(ConfigConstants.MDC_SECURE_DATA_KEY, ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY);
        properties.setProperty(ConfigConstants.MDC_TRACE_ID_KEYS, ConfigConstants.DEFAULT_MDC_TRACE_ID_KEYS);
        properties.setProperty(ConfigConstants.MDC_PUB_KEY_FINGERPRINT, ConfigConstants.DEFAULT_MDC_PUB_KEY_FINGERPRINT);
        properties.setProperty(ConfigConstants.CRYPTO_PROVIDER, ConfigConstants.DEFAULT_CRYPTO_PROVIDER);
        properties.setProperty(ConfigConstants.SM2_CURVE_NAME, ConfigConstants.DEFAULT_SM2_CURVE_NAME);
        properties.setProperty(ConfigConstants.SM2_CIPHER_TRANSFORMATION, ConfigConstants.DEFAULT_SM2_CIPHER_TRANSFORMATION);
        properties.setProperty(ConfigConstants.SM4_CIPHER_TRANSFORMATION, ConfigConstants.DEFAULT_SM4_CIPHER_TRANSFORMATION);
    }

    /**
     * 获取属性值
     *
     * @param key          属性键
     * @param defaultValue 如果属性未找到则使用默认值
     * @return 属性值或默认值
     */
    public String getProperty(String key, String defaultValue) {
        if (!initialized) {
            try {
                initialize();
            } catch (Exception e) {
                // 初始化失败时直接返回默认值，避免重复初始化
                return defaultValue;
            }
        }
        return properties.getProperty(key, defaultValue);
    }

    public String getPublicKeyFingerprint() {
        String publicKeyBase64 = getProperty(ConfigConstants.ECC_PUBLIC_KEY, "");
        if (publicKeyBase64 == null) {
            return null;
        }
        String cachedKey = this.cachedPublicKeyBase64;
        if (cachedKey != null && cachedKey.equals(publicKeyBase64)) {
            return cachedPublicKeyFingerprint;
        }
        String fingerprint = EccCore.publicKeyFingerprint(publicKeyBase64);
        this.cachedPublicKeyBase64 = publicKeyBase64;
        this.cachedPublicKeyFingerprint = fingerprint;
        return fingerprint;
    }

    /**
     * 获取整数属性值
     *
     * @param key          属性键
     * @param defaultValue 如果属性未找到或无效则使用默认值
     * @return 属性值或默认值
     */
    public int getIntProperty(String key, int defaultValue) {
        try {
            String value = getProperty(key, null);
            if (value != null) {
                return Integer.parseInt(value);
            }
        } catch (NumberFormatException e) {
            // 忽略，返回默认值
        }
        return defaultValue;
    }

    /**
     * 获取布尔属性值
     *
     * @param key          属性键
     * @param defaultValue 如果属性未找到或无效则使用默认值
     * @return 属性值或默认值
     */
    public boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = getProperty(key, null);
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return defaultValue;
    }

    /**
     * 获取双精度浮点属性值
     *
     * @param key          属性键
     * @param defaultValue 如果属性未找到或无效则使用默认值
     * @return 属性值或默认值
     */
    public double getDoubleProperty(String key, double defaultValue) {
        try {
            String value = getProperty(key, null);
            if (value != null) {
                return Double.parseDouble(value);
            }
        } catch (NumberFormatException e) {
            // 忽略，返回默认值
        }
        return defaultValue;
    }

    /**
     * 设置属性值
     *
     * @param key   属性键
     * @param value 属性值
     */
    public void setProperty(String key, String value) {
        properties.setProperty(key, value);
        if (ConfigConstants.ECC_PUBLIC_KEY.equals(key)) {
            this.cachedPublicKeyBase64 = value;
            this.cachedPublicKeyFingerprint = EccCore.publicKeyFingerprint(value);
        }
    }

    /**
     * 检查是否已初始化
     *
     * @return 如果已初始化则为true，否则为false
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * 将配置保存到文件
     *
     * @param file 要保存到的文件
     * @throws Exception 如果保存失败
     */
    public void save(File file) throws Exception {
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
            properties.store(writer, "SecureLog ECC配置");
        }
    }
}
