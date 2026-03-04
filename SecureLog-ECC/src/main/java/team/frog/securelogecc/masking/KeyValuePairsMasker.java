/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * key/value 片段脱敏器。
 *
 * <p>用于处理非 JSON 的普通日志文本中出现的键值对片段，例如：
 * {@code password=xxx}、{@code token: abc}、{@code mobile：13800138000}。</p>
 *
 * <p>策略：
 * <ul>
 *   <li>通过正则在整段文本中查找 key-value 形态</li>
 *   <li>仅当 key 命中敏感 key（或隐式敏感 key，如 password/pwd/pass）时才替换</li>
 *   <li>替换前将原值写入 {@link SensitiveDataCollector}，用于构建 SECURE_DATA</li>
 * </ul>
 * </p>
 */
public class KeyValuePairsMasker {
    private final StructuredMaskingConfig config;
    private final MaskingRules rules;
    private final Pattern keyValuePattern = Pattern.compile("(?i)\\b([A-Za-z_][A-Za-z0-9_]{0,63})\\b\\s*[:=：]\\s*(\\\"([^\\\"]*)\\\"|'([^']*)'|([^,，\\s}\\]\\)\\\"']+))");

    public KeyValuePairsMasker(StructuredMaskingConfig config, MaskingRules rules) {
        this.config = config;
        this.rules = rules;
    }

    public String maskKeyValuePairs(String message, SensitiveDataCollector collector) {
        if (message == null || message.isEmpty()) {
            return message;
        }
        Matcher m = keyValuePattern.matcher(message);
        StringBuilder sb = new StringBuilder(message.length());
        int last = 0;
        boolean changed = false;
        while (m.find()) {
            String key = m.group(1);
            String keyLower = key == null ? "" : key.toLowerCase(Locale.ROOT);

            if (!config.isSensitiveKey(keyLower) && !isImplicitSensitiveKey(keyLower)) {
                continue;
            }

            int valueGroup = findValueGroupIndex(m);
            if (valueGroup <= 0) {
                continue;
            }
            String value = m.group(valueGroup);
            if (rules.isEmptyLike(value)) {
                continue;
            }

            String masked = maskBySensitiveKey(keyLower, value);
            if (masked == null || masked.equals(value)) {
                continue;
            }

            collector.put(keyLower, value);
            int valueStart = m.start(valueGroup);
            int valueEnd = m.end(valueGroup);
            sb.append(message, last, valueStart);
            sb.append(masked);
            last = valueEnd;
            changed = true;
        }
        if (!changed) {
            return message;
        }
        sb.append(message, last, message.length());
        return sb.toString();
    }

    private boolean isImplicitSensitiveKey(String keyLower) {
        if (keyLower == null) {
            return false;
        }
        return keyLower.contains("password") || keyLower.equals("pwd") || keyLower.equals("pass");
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
            if (rules.isPhoneOrTel(value)) {
                return rules.maskPhone(value);
            }
            return value;
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

    private int findValueGroupIndex(Matcher m) {
        if (m.group(3) != null) {
            return 3;
        }
        if (m.group(4) != null) {
            return 4;
        }
        if (m.group(5) != null) {
            return 5;
        }
        return -1;
    }
}
