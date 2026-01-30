/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.config;

/**
 * 配置常量类
 * 集中管理所有配置键和默认值
 */
public class ConfigConstants {

    /** ECC 公钥配置键。 */
    public static final String ECC_PUBLIC_KEY = "ecc.public.key";

    /** 密码学 Provider 配置键。 */
    public static final String CRYPTO_PROVIDER = "ecc.crypto.provider";
    /** 默认密码学 Provider。 */
    public static final String DEFAULT_CRYPTO_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    /** SM2 曲线名称配置键。 */
    public static final String SM2_CURVE_NAME = "ecc.sm2.curve.name";
    /** 默认 SM2 曲线名称。 */
    public static final String DEFAULT_SM2_CURVE_NAME = "sm2p256v1";

    /** SM2 加密 transformation 配置键。 */
    public static final String SM2_CIPHER_TRANSFORMATION = "ecc.sm2.cipher.transformation";
    /** 默认 SM2 加密 transformation。 */
    public static final String DEFAULT_SM2_CIPHER_TRANSFORMATION = "SM2";

    /** SM4 加密 transformation 配置键。 */
    public static final String SM4_CIPHER_TRANSFORMATION = "ecc.sm4.cipher.transformation";
    /** 默认 SM4 加密 transformation。 */
    public static final String DEFAULT_SM4_CIPHER_TRANSFORMATION = "SM4/GCM/NoPadding";

    /** 会话密钥缓存大小配置键。 */
    public static final String SESSION_KEY_CACHE_SIZE = "ecc.session.key.cache.size";
    /** 默认会话密钥缓存大小。 */
    public static final int DEFAULT_SESSION_KEY_CACHE_SIZE = 30000;

    /** 会话密钥缓存缓冲比例配置键。 */
    public static final String SESSION_KEY_CACHE_BUFFER_PERCENTAGE = "ecc.session.key.cache.buffer.percentage";
    /** 默认会话密钥缓存缓冲比例。 */
    public static final double DEFAULT_SESSION_KEY_CACHE_BUFFER_PERCENTAGE = 0.05;

    /** 系统密钥缓存大小配置键。 */
    public static final String SYSTEM_KEY_CACHE_SIZE = "ecc.system.key.cache.size";
    /** 默认系统密钥缓存大小。 */
    public static final int DEFAULT_SYSTEM_KEY_CACHE_SIZE = 1000;

    /** 系统密钥缓存缓冲比例配置键。 */
    public static final String SYSTEM_KEY_CACHE_BUFFER_PERCENTAGE = "ecc.system.key.cache.buffer.percentage";
    /** 默认系统密钥缓存缓冲比例。 */
    public static final double DEFAULT_SYSTEM_KEY_CACHE_BUFFER_PERCENTAGE = 0.1;

    /** 系统标识符变化间隔（分钟）配置键。 */
    public static final String SYSTEM_ID_CHANGE_INTERVAL_MINUTES = "ecc.system.id.change.interval.minutes";
    /** 默认系统标识符变化间隔（分钟）。 */
    public static final int DEFAULT_SYSTEM_ID_CHANGE_INTERVAL_MINUTES = 15;

    /** 每秒毫秒数。 */
    public static final long MILLIS_PER_SECOND = 1000L;
    /** 每分钟毫秒数。 */
    public static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    /** 每小时毫秒数。 */
    public static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;
    /** 每天毫秒数。 */
    public static final long MILLIS_PER_DAY = 24 * MILLIS_PER_HOUR;

    /** MDC 中 SECURE_DATA 的配置键。 */
    public static final String MDC_SECURE_DATA_KEY = "mdc.secure.data.key";
    /** 默认 MDC SECURE_DATA key。 */
    public static final String DEFAULT_MDC_SECURE_DATA_KEY = "SECURE_DATA";

    /** MDC 中 traceId key 列表配置键。 */
    public static final String MDC_TRACE_ID_KEYS = "mdc.trace.id.keys";
    /** 默认 traceId key 列表。 */
    public static final String DEFAULT_MDC_TRACE_ID_KEYS = "trace_id,traceId,requestId,correlationId,X-Trace-Code,X-Trace-Id";
    /** MDC 中公钥指纹 key 配置键。 */
    public static final String MDC_PUB_KEY_FINGERPRINT = "mdc.pub.key.fingerprint.key";
    /** 默认 MDC 公钥指纹 key。 */
    public static final String DEFAULT_MDC_PUB_KEY_FINGERPRINT = "PUB_KEY_FINGERPRINT";

    /** 强敏感 key 列表配置键。 */
    public static final String MASKING_SENSITIVE_KEYS = "ecc.masking.sensitive.keys";
    /** 默认强敏感 key 列表。 */
    public static final String DEFAULT_MASKING_SENSITIVE_KEYS = "password,pwd,pass,token,access_token,clientSecret,secret,apiKey,idcard,cardNumber,jbrCardNumber,mobile,phone,tel,email,address";

    /** token-like key 列表配置键。 */
    public static final String MASKING_TOKENLIKE_KEYS = "ecc.masking.tokenlike.keys";
    /** 默认 token-like key 列表。 */
    public static final String DEFAULT_MASKING_TOKENLIKE_KEYS = "token,access_token,clientSecret,secret,apiKey,key,auth,credential";

    /** querystring 脱敏开关配置键。 */
    public static final String MASKING_QUERYSTRING_ENABLED = "ecc.masking.querystring.enabled";
    /** 默认 querystring 脱敏开关。 */
    public static final boolean DEFAULT_MASKING_QUERYSTRING_ENABLED = true;

    /** 兜底脱敏开关配置键。 */
    public static final String MASKING_FALLBACK_ENABLED = "ecc.masking.fallback.enabled";
    /** 默认兜底脱敏开关。 */
    public static final boolean DEFAULT_MASKING_FALLBACK_ENABLED = true;

    /** 地址识别需包含区域关键字配置键。 */
    public static final String MASKING_ADDRESS_REQUIRE_REGION = "ecc.masking.address.require.region";
    /** 默认地址识别需包含区域关键字。 */
    public static final boolean DEFAULT_MASKING_ADDRESS_REQUIRE_REGION = true;
    /** 地址识别需包含详情关键字配置键。 */
    public static final String MASKING_ADDRESS_REQUIRE_DETAIL = "ecc.masking.address.require.detail";
    /** 默认地址识别需包含详情关键字。 */
    public static final boolean DEFAULT_MASKING_ADDRESS_REQUIRE_DETAIL = true;

    /** 地址区域关键字配置键。 */
    public static final String MASKING_ADDRESS_REGION_KEYWORDS = "ecc.masking.address.region.keywords";
    /** 默认地址区域关键字列表。 */
    public static final String DEFAULT_MASKING_ADDRESS_REGION_KEYWORDS = "省,市,区,县";
    /** 地址详情关键字配置键。 */
    public static final String MASKING_ADDRESS_DETAIL_KEYWORDS = "ecc.masking.address.detail.keywords";
    /** 默认地址详情关键字列表。 */
    public static final String DEFAULT_MASKING_ADDRESS_DETAIL_KEYWORDS = "街,路,道,巷,镇,乡,号,院,楼,室";
    /** 地址排除关键字配置键。 */
    public static final String MASKING_ADDRESS_EXCLUDE_KEYWORDS = "ecc.masking.address.exclude.keywords";
    /** 默认地址排除关键字列表。 */
    public static final String DEFAULT_MASKING_ADDRESS_EXCLUDE_KEYWORDS = "";

    /** 高熵 token 脱敏开关配置键。 */
    public static final String MASKING_HIGH_ENTROPY_ENABLED = "ecc.masking.high.entropy.enabled";
    /** 默认高熵 token 脱敏开关。 */
    public static final boolean DEFAULT_MASKING_HIGH_ENTROPY_ENABLED = true;
    /** 高熵 token 需包含大小写与数字开关配置键。 */
    public static final String MASKING_HIGH_ENTROPY_REQUIRE_UPPER_LOWER_DIGIT = "ecc.masking.high.entropy.require.upper.lower.digit";
    /** 默认高熵 token 需包含大小写与数字。 */
    public static final boolean DEFAULT_MASKING_HIGH_ENTROPY_REQUIRE_UPPER_LOWER_DIGIT = true;

    /** token 前缀保留长度配置键。 */
    public static final String MASKING_TOKEN_KEEP_PREFIX = "ecc.masking.token.keep.prefix";
    /** 默认 token 前缀保留长度。 */
    public static final int DEFAULT_MASKING_TOKEN_KEEP_PREFIX = 4;
    /** token 后缀保留长度配置键。 */
    public static final String MASKING_TOKEN_KEEP_SUFFIX = "ecc.masking.token.keep.suffix";
    /** 默认 token 后缀保留长度。 */
    public static final int DEFAULT_MASKING_TOKEN_KEEP_SUFFIX = 4;

    /** 最大 value 长度配置键。 */
    public static final String MASKING_MAX_VALUE_LENGTH = "ecc.masking.max.value.length";
    /** 默认最大 value 长度。 */
    public static final int DEFAULT_MASKING_MAX_VALUE_LENGTH = 50;

    /** 高熵 token 最小长度配置键。 */
    public static final String MASKING_HIGH_ENTROPY_MIN_LENGTH = "ecc.masking.high.entropy.min.length";
    /** 默认高熵 token 最小长度。 */
    public static final int DEFAULT_MASKING_HIGH_ENTROPY_MIN_LENGTH = 20;
    /** 高熵 token 阈值配置键。 */
    public static final String MASKING_HIGH_ENTROPY_THRESHOLD = "ecc.masking.high.entropy.threshold";
    /** 默认高熵 token 阈值。 */
    public static final double DEFAULT_MASKING_HIGH_ENTROPY_THRESHOLD = 3.5d;

    /** 防止实例化。 */
    private ConfigConstants() {
    }
}
