package team.frog.securelogecc.config;

/**
 * 配置常量类
 * 集中管理所有配置键和默认值
 */
public class ConfigConstants {

    // ECC公钥配置
    public static final String ECC_PUBLIC_KEY = "ecc.public.key";

    // 密码学配置
    public static final String CRYPTO_PROVIDER = "ecc.crypto.provider";
    public static final String DEFAULT_CRYPTO_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    public static final String SM2_CURVE_NAME = "ecc.sm2.curve.name";
    public static final String DEFAULT_SM2_CURVE_NAME = "sm2p256v1";

    public static final String SM2_CIPHER_TRANSFORMATION = "ecc.sm2.cipher.transformation";
    public static final String DEFAULT_SM2_CIPHER_TRANSFORMATION = "SM2";

    public static final String SM4_CIPHER_TRANSFORMATION = "ecc.sm4.cipher.transformation";
    public static final String DEFAULT_SM4_CIPHER_TRANSFORMATION = "SM4/GCM/NoPadding";

    // 会话密钥缓存配置
    public static final String SESSION_KEY_CACHE_SIZE = "ecc.session.key.cache.size";
    public static final int DEFAULT_SESSION_KEY_CACHE_SIZE = 30000;

    public static final String SESSION_KEY_CACHE_BUFFER_PERCENTAGE = "ecc.session.key.cache.buffer.percentage";
    public static final double DEFAULT_SESSION_KEY_CACHE_BUFFER_PERCENTAGE = 0.05;

    // 系统密钥缓存配置
    public static final String SYSTEM_KEY_CACHE_SIZE = "ecc.system.key.cache.size";
    public static final int DEFAULT_SYSTEM_KEY_CACHE_SIZE = 1000;

    public static final String SYSTEM_KEY_CACHE_BUFFER_PERCENTAGE = "ecc.system.key.cache.buffer.percentage";
    public static final double DEFAULT_SYSTEM_KEY_CACHE_BUFFER_PERCENTAGE = 0.1;

    // 系统标识符变化间隔配置
    public static final String SYSTEM_ID_CHANGE_INTERVAL_MINUTES = "ecc.system.id.change.interval.minutes";
    public static final int DEFAULT_SYSTEM_ID_CHANGE_INTERVAL_MINUTES = 15;

    // 时间单位常量
    public static final long MILLIS_PER_SECOND = 1000L;
    public static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    public static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;
    public static final long MILLIS_PER_DAY = 24 * MILLIS_PER_HOUR;

    // MDC配置
    public static final String MDC_SECURE_DATA_KEY = "mdc.secure.data.key";
    public static final String DEFAULT_MDC_SECURE_DATA_KEY = "SECURE_DATA";

    public static final String MDC_TRACE_ID_KEYS = "mdc.trace.id.keys";
    public static final String DEFAULT_MDC_TRACE_ID_KEYS = "trace_id,traceId,requestId,correlationId,X-Trace-Code,X-Trace-Id";

    public static final String MASKING_SENSITIVE_KEYS = "ecc.masking.sensitive.keys";
    public static final String DEFAULT_MASKING_SENSITIVE_KEYS = "password,pwd,pass,token,access_token,clientSecret,secret,apiKey,idcard,cardNumber,jbrCardNumber,mobile,phone,tel,email,address";

    public static final String MASKING_TOKENLIKE_KEYS = "ecc.masking.tokenlike.keys";
    public static final String DEFAULT_MASKING_TOKENLIKE_KEYS = "token,access_token,clientSecret,secret,apiKey,key,auth,credential";

    public static final String MASKING_QUERYSTRING_ENABLED = "ecc.masking.querystring.enabled";
    public static final boolean DEFAULT_MASKING_QUERYSTRING_ENABLED = true;

    public static final String MASKING_FALLBACK_ENABLED = "ecc.masking.fallback.enabled";
    public static final boolean DEFAULT_MASKING_FALLBACK_ENABLED = true;

    public static final String MASKING_ADDRESS_REQUIRE_REGION = "ecc.masking.address.require.region";
    public static final boolean DEFAULT_MASKING_ADDRESS_REQUIRE_REGION = true;
    public static final String MASKING_ADDRESS_REQUIRE_DETAIL = "ecc.masking.address.require.detail";
    public static final boolean DEFAULT_MASKING_ADDRESS_REQUIRE_DETAIL = true;

    public static final String MASKING_ADDRESS_REGION_KEYWORDS = "ecc.masking.address.region.keywords";
    public static final String DEFAULT_MASKING_ADDRESS_REGION_KEYWORDS = "省,市,区,县";
    public static final String MASKING_ADDRESS_DETAIL_KEYWORDS = "ecc.masking.address.detail.keywords";
    public static final String DEFAULT_MASKING_ADDRESS_DETAIL_KEYWORDS = "街,路,道,巷,镇,乡,号,院,楼,室";
    public static final String MASKING_ADDRESS_EXCLUDE_KEYWORDS = "ecc.masking.address.exclude.keywords";
    public static final String DEFAULT_MASKING_ADDRESS_EXCLUDE_KEYWORDS = "";

    public static final String MASKING_HIGH_ENTROPY_ENABLED = "ecc.masking.high.entropy.enabled";
    public static final boolean DEFAULT_MASKING_HIGH_ENTROPY_ENABLED = true;
    public static final String MASKING_HIGH_ENTROPY_REQUIRE_UPPER_LOWER_DIGIT = "ecc.masking.high.entropy.require.upper.lower.digit";
    public static final boolean DEFAULT_MASKING_HIGH_ENTROPY_REQUIRE_UPPER_LOWER_DIGIT = true;

    public static final String MASKING_TOKEN_KEEP_PREFIX = "ecc.masking.token.keep.prefix";
    public static final int DEFAULT_MASKING_TOKEN_KEEP_PREFIX = 4;
    public static final String MASKING_TOKEN_KEEP_SUFFIX = "ecc.masking.token.keep.suffix";
    public static final int DEFAULT_MASKING_TOKEN_KEEP_SUFFIX = 4;

    public static final String MASKING_MAX_VALUE_LENGTH = "ecc.masking.max.value.length";
    public static final int DEFAULT_MASKING_MAX_VALUE_LENGTH = 50;

    public static final String MASKING_HIGH_ENTROPY_MIN_LENGTH = "ecc.masking.high.entropy.min.length";
    public static final int DEFAULT_MASKING_HIGH_ENTROPY_MIN_LENGTH = 20;
    public static final String MASKING_HIGH_ENTROPY_THRESHOLD = "ecc.masking.high.entropy.threshold";
    public static final double DEFAULT_MASKING_HIGH_ENTROPY_THRESHOLD = 3.5d;

    private ConfigConstants() {
        // 防止实例化
    }
}
