/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import java.util.Map;

/**
 * 结构化优先的日志脱敏引擎。
 *
 * <p>该引擎负责在“尽量不破坏原日志格式”的前提下脱敏敏感信息，并提取原始敏感值供加密写入 SECURE_DATA。</p>
 *
 * <p>处理顺序：
 * <ol>
 *   <li>JSON：支持嵌套对象/数组路径；字符串值中可递归处理嵌套 JSON、以及 querystring</li>
 *   <li>SQL Parameters：识别形如 "Parameters:" 的参数列表，优先处理 String 值</li>
 *   <li>URL query：对文本中出现的 "?a=b&c=d" 片段做脱敏</li>
 *   <li>纯 querystring：对整条文本形如 "a=b&c=d" 的情况做逐项脱敏</li>
 *   <li>key/value：识别 "key=value"、"key: value" 等片段并按敏感 key 脱敏</li>
 *   <li>纯文本兜底：仅扫描身份证/手机号/邮箱/严格地址</li>
 * </ol>
 * </p>
 */
public class StructuredMaskingEngine {
    /**
     * 结构化优先脱敏引擎的输出结果。
     *
     * <p>masked：脱敏后的日志文本（保持原格式，仅做必要替换）</p>
     * <p>extracted：提取到的原始敏感值（key 为路径化字段名，value 为原始值），用于构建 SECURE_DATA</p>
     */
    public static final class Result {
        private final String masked;
        private final Map<String, String> extracted;

        public Result(String masked, Map<String, String> extracted) {
            this.masked = masked;
            this.extracted = extracted;
        }

        public String getMasked() {
            return masked;
        }

        public Map<String, String> getExtracted() {
            return extracted;
        }
    }

    private final StructuredMaskingConfig config;
    private final MaskingRules rules;
    private final QueryStringMasker queryStringMasker;
    private final SqlParametersMasker sqlParametersMasker;
    private final PlainTextFallbackMasker plainTextFallbackMasker;
    private final JsonStructuredMasker jsonStructuredMasker;
    private final KeyValuePairsMasker keyValuePairsMasker;

    public StructuredMaskingEngine(StructuredMaskingConfig config) {
        this.config = config;
        this.rules = new MaskingRules(config);
        this.queryStringMasker = new QueryStringMasker(config, rules);
        this.sqlParametersMasker = new SqlParametersMasker(rules);
        this.plainTextFallbackMasker = new PlainTextFallbackMasker(config, rules);
        this.jsonStructuredMasker = new JsonStructuredMasker(config, rules, queryStringMasker);
        this.keyValuePairsMasker = new KeyValuePairsMasker(config, rules);
    }

    /**
     * 对单条日志文本进行结构化优先脱敏。
     *
     * <p>处理顺序：
     * <ol>
     *   <li>JSON：支持嵌套对象、数组路径，字符串值中可递归处理嵌套 JSON / querystring</li>
     *   <li>SQL Parameters：识别 "Parameters:" 形态，仅处理 String 值</li>
     *   <li>纯 querystring：对形如 "a=b&c=d" 的整条文本做逐项脱敏</li>
     *   <li>key/value 对：识别 "password=xxx"、"password: xxx" 等形态，仅对敏感 key 命中项脱敏</li>
     *   <li>纯文本兜底：仅扫描身份证/手机号/邮箱/严格地址，不做高熵 token 裸扫</li>
     * </ol>
     *
     * <p>注：空值（null、""、空白、字面量 "null"）不会参与脱敏与提取。</p>
     */
    public Result mask(String message) {
        SensitiveDataCollector collector = new SensitiveDataCollector();
        if (message == null || message.isEmpty()) {
            return new Result(message, collector.snapshot());
        }

        String trimmed = message.trim();
        if (looksLikeJson(trimmed)) {
            JsonStructuredMasker.JsonMaskResult r = jsonStructuredMasker.tryMaskJson(message, collector);
            if (r != null) {
                return new Result(r.getMasked(), collector.snapshot());
            }
        }

        String maskedSqlParams = sqlParametersMasker.maskSqlParametersLine(message, collector);
        if (!maskedSqlParams.equals(message)) {
            return new Result(maskedSqlParams, collector.snapshot());
        }

        String urlQueryMasked = queryStringMasker.maskUrlQueryInText(message, "query", collector);
        if (!urlQueryMasked.equals(message)) {
            return new Result(urlQueryMasked, collector.snapshot());
        }

        if (config.isQueryStringEnabled() && looksLikeQueryString(trimmed)) {
            String masked = queryStringMasker.maskQueryString(message, "query", collector);
            return new Result(masked, collector.snapshot());
        }

        String kvMasked = keyValuePairsMasker.maskKeyValuePairs(message, collector);
        if (!kvMasked.equals(message)) {
            return new Result(kvMasked, collector.snapshot());
        }

        String fallback = plainTextFallbackMasker.maskPlainText(message, collector);
        return new Result(fallback, collector.snapshot());
    }

    private boolean looksLikeJson(String trimmed) {
        if (trimmed.isEmpty()) {
            return false;
        }
        char c0 = trimmed.charAt(0);
        char cLast = trimmed.charAt(trimmed.length() - 1);
        return (c0 == '{' && cLast == '}') || (c0 == '[' && cLast == ']');
    }

    private boolean looksLikeQueryString(String trimmed) {
        if (trimmed.indexOf('=') <= 0) {
            return false;
        }
        return trimmed.indexOf('&') >= 0;
    }
}

