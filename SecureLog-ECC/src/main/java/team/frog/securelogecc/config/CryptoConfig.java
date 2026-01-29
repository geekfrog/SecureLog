package team.frog.securelogecc.config;

import team.frog.securelogecc.manager.ConfigManager;

import java.security.Provider;
import java.security.Security;

/**
 * 密码学 Provider 与算法配置读取入口。
 *
 * <p>职责：
 * <ul>
 *   <li>从 {@code securelog-ecc.properties} 读取并解析 JCE Provider（默认 BouncyCastle）</li>
 *   <li>按需注册 Provider 到 JCE，并缓存 providerName，避免重复加载</li>
 *   <li>暴露 SM2/SM4 的 transformation、曲线名等配置读取方法</li>
 * </ul>
 * </p>
 *
 * <p>该类为纯静态工具类，首次调用会触发 Provider 的加载与注册（若未注册）。</p>
 */
public final class CryptoConfig {
    private static volatile String cachedProviderConfig;
    private static volatile String cachedProviderName;

    private CryptoConfig() {
    }

    public static String getCryptoProvider() {
        ensureProviderAvailable();
        return cachedProviderName;
    }

    public static void ensureProviderAvailable() {
        String providerConfig = ConfigManager.getInstance().getProperty(
                ConfigConstants.CRYPTO_PROVIDER,
                ConfigConstants.DEFAULT_CRYPTO_PROVIDER
        );

        String providerName = cachedProviderName;
        if (providerName != null && providerConfig.equals(cachedProviderConfig) && Security.getProvider(providerName) != null) {
            return;
        }

        Provider resolvedProvider = resolveProvider(providerConfig);
        cachedProviderConfig = providerConfig;
        cachedProviderName = resolvedProvider.getName();
    }

    public static String getSm2CurveName() {
        return ConfigManager.getInstance().getProperty(ConfigConstants.SM2_CURVE_NAME, ConfigConstants.DEFAULT_SM2_CURVE_NAME);
    }

    public static String getSm2CipherTransformation() {
        return ConfigManager.getInstance().getProperty(ConfigConstants.SM2_CIPHER_TRANSFORMATION, ConfigConstants.DEFAULT_SM2_CIPHER_TRANSFORMATION);
    }

    public static String getSm4CipherTransformation() {
        return ConfigManager.getInstance().getProperty(ConfigConstants.SM4_CIPHER_TRANSFORMATION, ConfigConstants.DEFAULT_SM4_CIPHER_TRANSFORMATION);
    }

    private static Provider resolveProvider(String providerConfig) {
        if (providerConfig == null || providerConfig.trim().isEmpty()) {
            throw new IllegalStateException("Crypto provider不可用: " + providerConfig);
        }

        String providerClassName = providerConfig.trim();
        if (providerClassName.indexOf('.') < 0) {
            throw new IllegalStateException("ecc.crypto.provider 必须配置Provider类全路径: " + providerConfig);
        }

        Provider loaded = tryLoadProviderByClassName(providerClassName);
        if (loaded != null) {
            return loaded;
        }

        throw new IllegalStateException("Crypto provider不可用: " + providerConfig);
    }

    private static Provider tryLoadProviderByClassName(String providerClassName) {
        try {
            Class<?> clazz = Class.forName(providerClassName);
            if (!Provider.class.isAssignableFrom(clazz)) {
                throw new IllegalStateException("不是合法的JCE Provider类: " + providerClassName);
            }

            Provider provider = (Provider) clazz.getDeclaredConstructor().newInstance();
            if (Security.getProvider(provider.getName()) == null) {
                Security.addProvider(provider);
            }
            Provider installed = Security.getProvider(provider.getName());
            if (installed == null) {
                throw new IllegalStateException("Provider注册失败: " + provider.getName());
            }
            return installed;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            return null;
        }
    }
}
