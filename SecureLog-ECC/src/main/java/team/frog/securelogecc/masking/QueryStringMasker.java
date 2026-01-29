package team.frog.securelogecc.masking;

import java.util.ArrayList;
import java.util.List;

/**
 * querystring 脱敏器。
 *
 * <p>支持两类场景：
 * <ul>
 *   <li>整条文本本身就是 querystring（形如 {@code a=b&c=d}）</li>
 *   <li>文本中包含 URL 查询串（形如 {@code /path?a=b&c=d#...}）</li>
 * </ul>
 * </p>
 *
 * <p>脱敏策略：
 * <ul>
 *   <li>优先按 key 命中：敏感 key 直接脱敏并提取原值</li>
 *   <li>其次按值形态：身份证/手机号/邮箱/严格地址</li>
 *   <li>对高熵 token 仅在 token-like key 命中时触发（降低误报）</li>
 * </ul>
 * </p>
 */
public class QueryStringMasker {
    private final StructuredMaskingConfig config;
    private final MaskingRules rules;

    public QueryStringMasker(StructuredMaskingConfig config, MaskingRules rules) {
        this.config = config;
        this.rules = rules;
    }

    /**
     * 对 querystring 进行逐项脱敏并提取原始敏感值。
     *
     * <p>输入形态示例：token=xxx&type=1&code=abc</p>
     * <p>处理方式：按 & 切分成多组 k=v，逐项按 key/值形态规则脱敏后再拼回。</p>
     *
     * <p>注意：
     * <ul>
     *   <li>value 为空（null、""、空白、字面量 "null"）将被忽略，不脱敏也不提取</li>
     *   <li>包含 { 或 : 的字符串将被视为非 querystring（避免误把 JSON 当 querystring）</li>
     * </ul>
     * </p>
     */
    public String maskQueryString(String queryString, String keyPrefix, SensitiveDataCollector collector) {
        if (queryString == null || queryString.isEmpty()) {
            return queryString;
        }
        if (!looksLikeQueryString(queryString)) {
            return queryString;
        }
        String[] parts = queryString.split("&", -1);
        List<String> masked = new ArrayList<>(parts.length);
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            int eq = part.indexOf('=');
            if (eq <= 0) {
                masked.add(part);
                continue;
            }
            String k = part.substring(0, eq);
            String v = part.substring(eq + 1);
            String fullKey = keyPrefix == null || keyPrefix.isEmpty() ? k : (keyPrefix + "." + k);

            String keyLower = k == null ? "" : k.toLowerCase();
            boolean sensitiveContext = config.isSensitiveKey(keyLower) || config.isTokenLikeKey(keyLower)
                    || keyLower.contains("password") || keyLower.equals("pwd") || keyLower.equals("pass");

            int j = i + 1;
            List<String> continuation = null;
            if (sensitiveContext) {
                while (j < parts.length && parts[j].indexOf('=') <= 0 && !parts[j].isEmpty()) {
                    if (continuation == null) {
                        continuation = new ArrayList<>();
                    }
                    continuation.add(parts[j]);
                    j++;
                }
            }

            String originalValue = v;
            if (continuation != null && !continuation.isEmpty()) {
                originalValue = originalValue + "&" + String.join("&", continuation);
            }

            MaskedValue mv = maskValueByKeyAndType(fullKey, k, originalValue, collector);
            masked.add(k + "=" + mv.masked);

            if (continuation != null && !continuation.isEmpty() && mv.changed) {
                for (int c = 0; c < continuation.size(); c++) {
                    masked.add("***");
                }
                i = j - 1;
            }
        }
        return String.join("&", masked);
    }

    public String maskUrlQueryInText(String message, String keyPrefix, SensitiveDataCollector collector) {
        if (message == null || message.isEmpty()) {
            return message;
        }
        int q = message.indexOf('?');
        if (q < 0 || q + 1 >= message.length()) {
            return message;
        }
        int end = findQueryEnd(message, q + 1);
        if (end <= q + 1) {
            return message;
        }
        String query = message.substring(q + 1, end);
        if (!looksLikeQueryString(query)) {
            return message;
        }
        String maskedQuery = maskQueryString(query, keyPrefix, collector);
        if (maskedQuery.equals(query)) {
            return message;
        }
        return message.substring(0, q + 1) + maskedQuery + message.substring(end);
    }

    private MaskedValue maskValueByKeyAndType(String fullKey, String key, String value, SensitiveDataCollector collector) {
        if (value == null) {
            return new MaskedValue("", false);
        }
        if (rules.isEmptyLike(value)) {
            return new MaskedValue(value, false);
        }

        String keyLower = key == null ? "" : key.toLowerCase();
        if (config.isSensitiveKey(keyLower)) {
            collector.put(fullKey, value);
            return new MaskedValue(maskBySensitiveKey(keyLower, value), true);
        }

        if (config.isTokenLikeKey(keyLower) && rules.looksLikeHighEntropyToken(value)) {
            collector.put(fullKey, value);
            return new MaskedValue(rules.maskToken(value), true);
        }

        if (rules.isIdCard(value)) {
            collector.put(fullKey, value);
            return new MaskedValue(rules.maskIdCard(value), true);
        }
        if (rules.isPhoneOrTel(value)) {
            collector.put(fullKey, value);
            return new MaskedValue(rules.maskPhone(value), true);
        }
        if (rules.isEmail(value)) {
            collector.put(fullKey, value);
            return new MaskedValue(rules.maskEmail(value), true);
        }
        if (rules.isStrictAddress(value)) {
            collector.put(fullKey, value);
            return new MaskedValue(rules.maskAddress(value), true);
        }

        return new MaskedValue(value, false);
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

    private boolean looksLikeQueryString(String s) {
        if (!config.isQueryStringEnabled()) {
            return false;
        }
        if (s.indexOf('=') <= 0) {
            return false;
        }
        boolean hasAmp = s.indexOf('&') >= 0;
        if (hasAmp) {
            return true;
        }
        if (s.indexOf('{') >= 0 || s.indexOf(':') >= 0) {
            return false;
        }
        return true;
    }

    private int findQueryEnd(String s, int start) {
        int hash = s.indexOf('#', start);
        int end = hash < 0 ? s.length() : hash;
        for (int i = start; i < end; i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) {
                return i;
            }
        }
        return end;
    }

    private static final class MaskedValue {
        private final String masked;
        private final boolean changed;

        private MaskedValue(String masked, boolean changed) {
            this.masked = masked;
            this.changed = changed;
        }
    }
}

