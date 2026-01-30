/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.manager.ConfigManager;

import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * 结构化脱敏配置快照。
 *
 * <p>该类会在构造时从 {@link ConfigManager} 读取配置，并将其解析为便于运行时判断的集合与阈值，
 * 避免在每条日志处理过程中重复解析字符串配置。</p>
 *
 * <p>主要配置项：
 * <ul>
 *   <li>敏感 key 列表（强敏感）：命中即脱敏并提取原值</li>
 *   <li>token-like key 列表：用于限定“高熵 token”识别的触发范围</li>
 *   <li>querystring/兜底开关、地址两阶段识别关键字与开关</li>
 *   <li>token 掩码保留前后缀长度、最大 value 长度、高熵阈值等</li>
 * </ul>
 * </p>
 */
public class StructuredMaskingConfig {
    private final Set<String> sensitiveKeys;
    private final Set<String> tokenLikeKeys;
    private final boolean queryStringEnabled;
    private final boolean fallbackEnabled;
    private final boolean addressRequireRegion;
    private final boolean addressRequireDetail;
    private final Set<String> addressRegionKeywords;
    private final Set<String> addressDetailKeywords;
    private final Set<String> addressExcludeKeywords;
    private final boolean highEntropyEnabled;
    private final boolean highEntropyRequireUpperLowerDigit;
    private final int tokenKeepPrefix;
    private final int tokenKeepSuffix;
    private final int maxValueLength;
    private final int highEntropyMinLength;
    private final double highEntropyThreshold;

    /**
     * 创建结构化脱敏配置快照。
     *
     * @param config 配置管理器
     */
    public StructuredMaskingConfig(ConfigManager config) {
        this.sensitiveKeys = parseKeySet(config.getProperty(ConfigConstants.MASKING_SENSITIVE_KEYS, ConfigConstants.DEFAULT_MASKING_SENSITIVE_KEYS));
        this.tokenLikeKeys = parseKeySet(config.getProperty(ConfigConstants.MASKING_TOKENLIKE_KEYS, ConfigConstants.DEFAULT_MASKING_TOKENLIKE_KEYS));
        this.queryStringEnabled = config.getBooleanProperty(ConfigConstants.MASKING_QUERYSTRING_ENABLED, ConfigConstants.DEFAULT_MASKING_QUERYSTRING_ENABLED);
        this.fallbackEnabled = config.getBooleanProperty(ConfigConstants.MASKING_FALLBACK_ENABLED, ConfigConstants.DEFAULT_MASKING_FALLBACK_ENABLED);
        this.addressRequireRegion = config.getBooleanProperty(ConfigConstants.MASKING_ADDRESS_REQUIRE_REGION, ConfigConstants.DEFAULT_MASKING_ADDRESS_REQUIRE_REGION);
        this.addressRequireDetail = config.getBooleanProperty(ConfigConstants.MASKING_ADDRESS_REQUIRE_DETAIL, ConfigConstants.DEFAULT_MASKING_ADDRESS_REQUIRE_DETAIL);
        this.addressRegionKeywords = parseStringSet(config.getProperty(ConfigConstants.MASKING_ADDRESS_REGION_KEYWORDS, ConfigConstants.DEFAULT_MASKING_ADDRESS_REGION_KEYWORDS));
        this.addressDetailKeywords = parseStringSet(config.getProperty(ConfigConstants.MASKING_ADDRESS_DETAIL_KEYWORDS, ConfigConstants.DEFAULT_MASKING_ADDRESS_DETAIL_KEYWORDS));
        this.addressExcludeKeywords = parseStringSet(config.getProperty(ConfigConstants.MASKING_ADDRESS_EXCLUDE_KEYWORDS, ConfigConstants.DEFAULT_MASKING_ADDRESS_EXCLUDE_KEYWORDS));
        this.highEntropyEnabled = config.getBooleanProperty(ConfigConstants.MASKING_HIGH_ENTROPY_ENABLED, ConfigConstants.DEFAULT_MASKING_HIGH_ENTROPY_ENABLED);
        this.highEntropyRequireUpperLowerDigit = config.getBooleanProperty(ConfigConstants.MASKING_HIGH_ENTROPY_REQUIRE_UPPER_LOWER_DIGIT, ConfigConstants.DEFAULT_MASKING_HIGH_ENTROPY_REQUIRE_UPPER_LOWER_DIGIT);

        this.tokenKeepPrefix = parseInt(config.getProperty(ConfigConstants.MASKING_TOKEN_KEEP_PREFIX, String.valueOf(ConfigConstants.DEFAULT_MASKING_TOKEN_KEEP_PREFIX)), ConfigConstants.DEFAULT_MASKING_TOKEN_KEEP_PREFIX);
        this.tokenKeepSuffix = parseInt(config.getProperty(ConfigConstants.MASKING_TOKEN_KEEP_SUFFIX, String.valueOf(ConfigConstants.DEFAULT_MASKING_TOKEN_KEEP_SUFFIX)), ConfigConstants.DEFAULT_MASKING_TOKEN_KEEP_SUFFIX);
        this.maxValueLength = parseInt(config.getProperty(ConfigConstants.MASKING_MAX_VALUE_LENGTH, String.valueOf(ConfigConstants.DEFAULT_MASKING_MAX_VALUE_LENGTH)), ConfigConstants.DEFAULT_MASKING_MAX_VALUE_LENGTH);
        this.highEntropyMinLength = parseInt(config.getProperty(ConfigConstants.MASKING_HIGH_ENTROPY_MIN_LENGTH, String.valueOf(ConfigConstants.DEFAULT_MASKING_HIGH_ENTROPY_MIN_LENGTH)), ConfigConstants.DEFAULT_MASKING_HIGH_ENTROPY_MIN_LENGTH);
        this.highEntropyThreshold = parseDouble(config.getProperty(ConfigConstants.MASKING_HIGH_ENTROPY_THRESHOLD, String.valueOf(ConfigConstants.DEFAULT_MASKING_HIGH_ENTROPY_THRESHOLD)), ConfigConstants.DEFAULT_MASKING_HIGH_ENTROPY_THRESHOLD);
    }

    /**
     * 判断 key 是否属于“强敏感 key”。
     *
     * <p>强敏感 key 会直接触发脱敏与提取（例如 password/mobile/idcard/email/address/token 等）。</p>
     */
    public boolean isSensitiveKey(String key) {
        if (key == null) {
            return false;
        }
        String k = normalizeKey(key);
        return sensitiveKeys.contains(k) || sensitiveKeys.contains(k.replace("_", ""));
    }

    /**
     * 判断 key 是否属于“token-like key”。
     *
     * <p>token-like key 用于约束“高熵 token”判断的触发范围，降低误报。</p>
     */
    public boolean isTokenLikeKey(String key) {
        if (key == null) {
            return false;
        }
        String k = normalizeKey(key);
        return tokenLikeKeys.contains(k) || tokenLikeKeys.contains(k.replace("_", ""));
    }

    /**
     * 是否启用 querystring 脱敏。
     *
     * @return 是否启用
     */
    public boolean isQueryStringEnabled() {
        return queryStringEnabled;
    }

    /**
     * 是否启用兜底脱敏。
     *
     * @return 是否启用
     */
    public boolean isFallbackEnabled() {
        return fallbackEnabled;
    }

    /**
     * 地址识别是否要求区域关键字。
     *
     * @return 是否要求
     */
    public boolean isAddressRequireRegion() {
        return addressRequireRegion;
    }

    /**
     * 地址识别是否要求详情关键字。
     *
     * @return 是否要求
     */
    public boolean isAddressRequireDetail() {
        return addressRequireDetail;
    }

    /**
     * 获取地址区域关键字集合。
     *
     * @return 地址区域关键字集合
     */
    public Set<String> getAddressRegionKeywords() {
        return addressRegionKeywords;
    }

    /**
     * 获取地址详情关键字集合。
     *
     * @return 地址详情关键字集合
     */
    public Set<String> getAddressDetailKeywords() {
        return addressDetailKeywords;
    }

    /**
     * 获取地址排除关键字集合。
     *
     * @return 地址排除关键字集合
     */
    public Set<String> getAddressExcludeKeywords() {
        return addressExcludeKeywords;
    }

    /**
     * 是否启用高熵 token 脱敏。
     *
     * @return 是否启用
     */
    public boolean isHighEntropyEnabled() {
        return highEntropyEnabled;
    }

    /**
     * 是否要求高熵 token 同时包含大小写与数字。
     *
     * @return 是否要求
     */
    public boolean isHighEntropyRequireUpperLowerDigit() {
        return highEntropyRequireUpperLowerDigit;
    }

    /**
     * 获取 token 前缀保留长度。
     *
     * @return 前缀保留长度
     */
    public int getTokenKeepPrefix() {
        return tokenKeepPrefix;
    }

    /**
     * 获取 token 后缀保留长度。
     *
     * @return 后缀保留长度
     */
    public int getTokenKeepSuffix() {
        return tokenKeepSuffix;
    }

    /**
     * 获取最大 value 长度。
     *
     * @return 最大 value 长度
     */
    public int getMaxValueLength() {
        return maxValueLength;
    }

    /**
     * 获取高熵 token 最小长度。
     *
     * @return 最小长度
     */
    public int getHighEntropyMinLength() {
        return highEntropyMinLength;
    }

    /**
     * 获取高熵 token 阈值。
     *
     * @return 阈值
     */
    public double getHighEntropyThreshold() {
        return highEntropyThreshold;
    }

    private Set<String> parseKeySet(String keysConfig) {
        if (keysConfig == null) {
            return Collections.emptySet();
        }
        String trimmed = keysConfig.trim();
        if (trimmed.isEmpty()) {
            return Collections.emptySet();
        }
        String[] parts = trimmed.split("\\s*[,;]\\s*");
        Set<String> set = new HashSet<>(parts.length * 2);
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            set.add(normalizeKey(p));
            set.add(normalizeKey(p.replace("_", "")));
        }
        return set;
    }

    private Set<String> parseStringSet(String config) {
        if (config == null) {
            return Collections.emptySet();
        }
        String trimmed = config.trim();
        if (trimmed.isEmpty()) {
            return Collections.emptySet();
        }
        String[] parts = trimmed.split("\\s*[,;]\\s*");
        Set<String> set = new HashSet<>(parts.length * 2);
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            set.add(p);
        }
        return set;
    }

    private String normalizeKey(String k) {
        if (k == null) {
            return "";
        }
        return k.trim().toLowerCase(Locale.ROOT);
    }

    private int parseInt(String s, int def) {
        if (s == null) {
            return def;
        }
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private double parseDouble(String s, double def) {
        if (s == null) {
            return def;
        }
        try {
            return Double.parseDouble(s.trim());
        } catch (Exception e) {
            return def;
        }
    }
}
