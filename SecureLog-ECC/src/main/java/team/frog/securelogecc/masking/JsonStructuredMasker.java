/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.util.*;

/**
 * JSON 结构化脱敏器。
 *
 * <p>使用 Jackson streaming API 解析整段 JSON，并仅对命中的字符串 value 做替换，
 * 尽量保持原 JSON 结构与字段顺序不变。</p>
 *
 * <p>能力点：
 * <ul>
 *   <li>按字段名（key）与值形态（身份证/手机号/邮箱/严格地址）脱敏，并提取原始敏感值</li>
 *   <li>对 token-like key 下的高熵 token 做掩码，降低误报</li>
 *   <li>对字符串 value 里的 querystring 做逐项脱敏</li>
 *   <li>对字符串 value 中嵌套的 JSON 做有限层级递归处理（默认最多 2 层）</li>
 * </ul>
 * </p>
 */
public class JsonStructuredMasker {
    /**
     * JSON 脱敏结果（脱敏后的 JSON 字符串）。
     *
     * <p>注意：该类不改变 JSON 的整体结构，仅对命中的字符串 value 做替换。
     * 替换时会保持 JSON 语法正确（对新值做必要的 JSON 转义）。</p>
     */
    public static final class JsonMaskResult {
        private final String masked;

        private JsonMaskResult(String masked) {
            this.masked = masked;
        }

        public String getMasked() {
            return masked;
        }
    }

    private static final int MAX_EMBEDDED_JSON_DEPTH = 2;

    private final StructuredMaskingConfig config;
    private final MaskingRules rules;
    private final QueryStringMasker queryStringMasker;
    private final JsonFactory jsonFactory = new JsonFactory();

    public JsonStructuredMasker(StructuredMaskingConfig config, MaskingRules rules, QueryStringMasker queryStringMasker) {
        this.config = config;
        this.rules = rules;
        this.queryStringMasker = queryStringMasker;
    }

    /**
     * 尝试将整条消息按 JSON 解析并脱敏。
     *
     * <p>如果解析失败（不是 JSON 或 JSON 不完整），返回 null，由上层继续走其他处理分支。</p>
     */
    public JsonMaskResult tryMaskJson(String message, SensitiveDataCollector collector) {
        try {
            return maskJsonInternal(message, collector, "", 0);
        } catch (Exception e) {
            return null;
        }
    }

    private JsonMaskResult maskJsonInternal(String json, SensitiveDataCollector collector, String prefix, int depth) throws Exception {
        List<Replacement> replacements = new ArrayList<>();

        Deque<PathFrame> stack = new ArrayDeque<>();
        String currentField = null;

        try (JsonParser parser = jsonFactory.createParser(json)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                if (token == JsonToken.FIELD_NAME) {
                    currentField = parser.getCurrentName();
                    continue;
                }
                if (token == JsonToken.START_OBJECT) {
                    if (currentField == null) {
                        incrementArrayElementIndex(stack, token);
                    }
                    stack.push(PathFrame.objectFrame(currentField));
                    currentField = null;
                    continue;
                }
                if (token == JsonToken.END_OBJECT) {
                    if (!stack.isEmpty()) {
                        stack.pop();
                    }
                    continue;
                }
                if (token == JsonToken.START_ARRAY) {
                    if (currentField == null) {
                        incrementArrayElementIndex(stack, token);
                    }
                    stack.push(PathFrame.arrayFrame(currentField));
                    currentField = null;
                    continue;
                }
                if (token == JsonToken.END_ARRAY) {
                    if (!stack.isEmpty()) {
                        stack.pop();
                    }
                    continue;
                }

                incrementArrayElementIndex(stack, token);
                String fieldForValue = currentField;
                currentField = null;

                if (fieldForValue == null) {
                    continue;
                }

                String fullPath = buildPath(prefix, stack, fieldForValue);

                if (token == JsonToken.VALUE_STRING) {
                    JsonLocation loc = parser.getTokenLocation();
                    int start = safeIntOffset(loc.getCharOffset());
                    int end = findStringTokenEnd(json, start);
                    if (start < 0 || end <= start || end > json.length()) {
                        continue;
                    }
                    String originalValue = parser.getText();
                    String maskedValue = maskStringValue(fullPath, fieldForValue, originalValue, collector, depth);
                    if (!originalValue.equals(maskedValue)) {
                        String escaped = escapeJsonString(maskedValue);
                        replacements.add(new Replacement(start, end, "\"" + escaped + "\""));
                    }
                    continue;
                }
            }
        }

        if (replacements.isEmpty()) {
            return new JsonMaskResult(json);
        }

        replacements.sort(Comparator.comparingInt((Replacement r) -> r.start).reversed());
        String out = json;
        for (Replacement r : replacements) {
            out = out.substring(0, r.start) + r.replacement + out.substring(r.end);
        }
        return new JsonMaskResult(out);
    }

    private String maskStringValue(String fullPath, String fieldName, String value, SensitiveDataCollector collector, int depth) {
        if (value == null) {
            return null;
        }
        if (rules.isEmptyLike(value)) {
            return value;
        }

        String key = fieldName == null ? "" : fieldName;
        String keyLower = key.toLowerCase();

        if (config.isSensitiveKey(keyLower)) {
            String masked = maskBySensitiveKey(keyLower, value);
            if (!masked.equals(value)) {
                collector.put(fullPath, value);
            }
            return masked;
        }

        if (config.isTokenLikeKey(keyLower) && rules.looksLikeHighEntropyToken(value)) {
            collector.put(fullPath, value);
            return rules.maskToken(value);
        }

        if (rules.isIdCard(value)) {
            collector.put(fullPath, value);
            return rules.maskIdCard(value);
        }
        if (rules.isPhoneOrTel(value)) {
            collector.put(fullPath, value);
            return rules.maskPhone(value);
        }
        if (rules.isEmail(value)) {
            collector.put(fullPath, value);
            return rules.maskEmail(value);
        }
        if (rules.isStrictAddress(value)) {
            collector.put(fullPath, value);
            return rules.maskAddress(value);
        }

        String qsMasked = queryStringMasker.maskQueryString(value, fullPath, collector);
        String out = qsMasked;

        if (depth < MAX_EMBEDDED_JSON_DEPTH) {
            String trimmed = out.trim();
            if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
                try {
                    JsonMaskResult inner = maskJsonInternal(out, collector, fullPath, depth + 1);
                    out = inner.masked;
                } catch (Exception ignored) {
                }
            }
        }

        return out;
    }

    private String maskBySensitiveKey(String keyLower, String value) {
        if (keyLower.contains("password") || keyLower.equals("pwd") || keyLower.equals("pass")) {
            return rules.maskPassword(value);
        }
        if (keyLower.contains("token") || keyLower.contains("secret") || keyLower.contains("apikey") || keyLower.contains("clientsecret") || keyLower.equals("key")) {
            return rules.maskToken(value);
        }
        if (keyLower.contains("idcard") || keyLower.contains("cardnumber")) {
            return rules.maskIdCard(value);
        }
        if (keyLower.contains("mobile") || keyLower.contains("phone") || keyLower.contains("tel")) {
            return rules.maskPhone(value);
        }
        if (keyLower.contains("email")) {
            return rules.maskEmail(value);
        }
        if (keyLower.contains("address")) {
            if (rules.isStrictAddress(value)) {
                return rules.maskAddress(value);
            }
            return value;
        }
        return "***";
    }

    private String buildPath(String prefix, Deque<PathFrame> stack, String fieldName) {
        StringBuilder sb = new StringBuilder(64);
        if (prefix != null && !prefix.isEmpty()) {
            sb.append(prefix);
        }
        List<PathFrame> frames = new ArrayList<>(stack);
        for (int i = frames.size() - 1; i >= 0; i--) {
            PathFrame f = frames.get(i);
            if (f.name != null && !f.name.isEmpty()) {
                if (sb.length() > 0) {
                    sb.append('.');
                }
                sb.append(f.name);
            }
            if (f.isArray) {
                sb.append('[').append(Math.max(0, f.index)).append(']');
            }
        }
        if (fieldName != null && !fieldName.isEmpty()) {
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(fieldName);
        }
        return sb.toString();
    }

    private void incrementArrayElementIndex(Deque<PathFrame> stack, JsonToken token) {
        if (stack.isEmpty()) {
            return;
        }
        PathFrame top = stack.peek();
        if (top == null || !top.isArray) {
            return;
        }
        if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY || token.isScalarValue()) {
            top.index++;
        }
    }

    private int safeIntOffset(long offset) {
        if (offset < 0 || offset > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) offset;
    }

    private int findStringTokenEnd(String json, int start) {
        if (start < 0 || start >= json.length()) {
            return -1;
        }
        int i = start;
        while (i < json.length() && json.charAt(i) != '"') {
            i++;
        }
        if (i >= json.length()) {
            return -1;
        }
        i++;
        boolean escaped = false;
        for (; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                return i + 1;
            }
        }
        return -1;
    }

    private String escapeJsonString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    sb.append(c);
                    break;
            }
        }
        return sb.toString();
    }

    private static final class Replacement {
        private final int start;
        private final int end;
        private final String replacement;

        private Replacement(int start, int end, String replacement) {
            this.start = start;
            this.end = end;
            this.replacement = replacement;
        }
    }

    private static final class PathFrame {
        private final String name;
        private final boolean isArray;
        private int index;

        private PathFrame(String name, boolean isArray) {
            this.name = name;
            this.isArray = isArray;
            this.index = -1;
        }

        private static PathFrame objectFrame(String name) {
            return new PathFrame(name, false);
        }

        private static PathFrame arrayFrame(String name) {
            return new PathFrame(name, true);
        }
    }
}

