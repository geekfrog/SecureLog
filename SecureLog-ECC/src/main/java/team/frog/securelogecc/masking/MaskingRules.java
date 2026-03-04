/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 脱敏规则与识别逻辑集合。
 *
 * <p>职责：
 * <ul>
 *   <li>按“值形态”识别：身份证、手机号/座机、邮箱、严格地址</li>
 *   <li>按“高熵特征”识别 token（结合 token-like key 降低误报）</li>
 *   <li>提供各类掩码方法（身份证/手机号/邮箱/地址/密码/token 等）</li>
 * </ul>
 * </p>
 *
 * <p>说明：识别与掩码策略会受 {@link StructuredMaskingConfig} 中的长度阈值、开关与关键字集合影响。</p>
 */
public class MaskingRules {
    private final StructuredMaskingConfig config;

    private final Pattern mobilePattern = Pattern.compile("(?<!\\d)(?:\\+?86[-\\s]?)?(1\\d{10})(?!\\d)");
    private final Pattern idCardPattern = Pattern.compile("(?<![0-9A-Za-z])([1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx])(?![0-9A-Za-z])");
    private final Pattern emailPattern = Pattern.compile("(?i)(?<![A-Z0-9._%+-])([A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\\.[A-Z]{2,})(?![A-Z0-9._%+-])");

    private final Pattern addressRegionPattern;
    private final Pattern addressDetailPattern;
    private final Pattern addressExcludePattern;

    public MaskingRules(StructuredMaskingConfig config) {
        this.config = config;
        this.addressRegionPattern = buildAddressRegionPattern(config.getAddressRegionKeywords());
        this.addressDetailPattern = buildKeywordPattern(config.getAddressDetailKeywords());
        this.addressExcludePattern = buildKeywordPattern(config.getAddressExcludeKeywords());
    }

    /**
     * 判断 value 是否“等价于空值”。
     *
     * <p>在日志中常见三种“无数据”表达：null、空字符串、字面量 "null"。
     * 这些值不参与脱敏与敏感值提取（避免产生无意义的 SECURE_DATA）。</p>
     */
    public boolean isEmptyLike(String value) {
        if (value == null) {
            return true;
        }
        String v = value.trim();
        if (v.isEmpty()) {
            return true;
        }
        return "null".equalsIgnoreCase(v);
    }

    public boolean isIdCard(String value) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.isEmpty() || v.length() > config.getMaxValueLength()) {
            return false;
        }
        if ("null".equalsIgnoreCase(v)) {
            return false;
        }
        return idCardPattern.matcher(v).matches();
    }

    public boolean isEmail(String value) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.isEmpty() || v.length() > config.getMaxValueLength()) {
            return false;
        }
        if ("null".equalsIgnoreCase(v)) {
            return false;
        }
        return emailPattern.matcher(v).matches();
    }

    public boolean isPhoneOrTel(String value) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.isEmpty() || v.length() > config.getMaxValueLength()) {
            return false;
        }
        if ("null".equalsIgnoreCase(v)) {
            return false;
        }
        return mobilePattern.matcher(v).matches();
    }

    public boolean isStrictAddress(String value) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.isEmpty() || v.length() > config.getMaxValueLength()) {
            return false;
        }
        if ("null".equalsIgnoreCase(v)) {
            return false;
        }
        if (addressExcludePattern != null && addressExcludePattern.matcher(v).find()) {
            return false;
        }

        boolean regionOk = !config.isAddressRequireRegion() || (addressRegionPattern != null && addressRegionPattern.matcher(v).find());
        boolean detailOk;
        if (!config.isAddressRequireDetail()) {
            detailOk = true;
        } else {
            detailOk = (addressDetailPattern != null && addressDetailPattern.matcher(v).find());
        }
        return regionOk && detailOk;
    }

    private Pattern buildAddressRegionPattern(Set<String> keywords) {
        String alt = buildKeywordAlternation(keywords);
        if (alt.isEmpty()) {
            return null;
        }
        return Pattern.compile("([\\u4e00-\\u9fa5]{2,}(?:" + alt + "))");
    }

    private Pattern buildKeywordPattern(Set<String> keywords) {
        String alt = buildKeywordAlternation(keywords);
        if (alt.isEmpty()) {
            return null;
        }
        return Pattern.compile("(?:" + alt + ")");
    }

    private String buildKeywordAlternation(Set<String> keywords) {
        if (keywords == null || keywords.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(keywords.size() * 4);
        boolean first = true;
        for (String kw : keywords) {
            if (kw == null) {
                continue;
            }
            String t = kw.trim();
            if (t.isEmpty()) {
                continue;
            }
            if (!first) {
                sb.append('|');
            }
            first = false;
            sb.append(Pattern.quote(t));
        }
        return first ? "" : sb.toString();
    }

    public String maskIdCard(String idCard) {
        String v = idCard == null ? "" : idCard.trim();
        if (v.length() < 10) {
            return "***";
        }
        String prefix = v.substring(0, Math.min(6, v.length()));
        String suffix = v.substring(Math.max(0, v.length() - 4));
        return prefix + "********" + suffix;
    }

    public String maskPhone(String phone) {
        String p = phone == null ? "" : phone.trim();
        if (p.length() < 7) {
            return "***";
        }
        int digitsCount = 0;
        for (int i = 0; i < p.length(); i++) {
            if (Character.isDigit(p.charAt(i))) {
                digitsCount++;
            }
        }
        if (digitsCount < 7) {
            return "***";
        }
        String digitsOnly = p.replaceAll("\\D+", "");
        if (digitsOnly.length() >= 11 && digitsOnly.startsWith("1")) {
            return digitsOnly.substring(0, 3) + "****" + digitsOnly.substring(digitsOnly.length() - 4);
        }
        if (digitsOnly.length() >= 10 && digitsOnly.startsWith("0")) {
            String prefix = digitsOnly.substring(0, 3);
            String suffix = digitsOnly.substring(digitsOnly.length() - 4);
            return prefix + "****" + suffix;
        }
        String prefix = p.substring(0, Math.min(2, p.length()));
        String suffix = p.substring(Math.max(0, p.length() - 2));
        return prefix + "***" + suffix;
    }

    public String maskEmail(String email) {
        String e = email == null ? "" : email.trim();
        int at = e.indexOf('@');
        if (at <= 0 || at >= e.length() - 1) {
            return "***";
        }
        String local = e.substring(0, at);
        String domain = e.substring(at);
        if (local.length() <= 2) {
            return local.substring(0, 1) + "***" + domain;
        }
        return local.substring(0, 1) + "***" + local.substring(local.length() - 1) + domain;
    }

    public String maskAddress(String address) {
        String a = address == null ? "" : address.trim();
        if (a.length() <= 4) {
            return "***";
        }
        String prefix = a.substring(0, 2);
        String suffix = a.substring(a.length() - 2);
        return prefix + "***" + suffix;
    }

    public String maskPassword(String password) {
        return "***";
    }

    public String maskToken(String token) {
        String t = token == null ? "" : token.trim();
        if (t.isEmpty()) {
            return "***";
        }
        if (t.length() <= config.getTokenKeepPrefix() + config.getTokenKeepSuffix()) {
            return "***";
        }
        String prefix = t.substring(0, Math.min(config.getTokenKeepPrefix(), t.length()));
        String suffix = t.substring(Math.max(0, t.length() - config.getTokenKeepSuffix()));
        return prefix + "***" + suffix;
    }

    public boolean looksLikePassword(String value) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        if (v.length() < 6 || v.length() > config.getMaxValueLength()) {
            return false;
        }
        if ("null".equalsIgnoreCase(v)) {
            return false;
        }
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (Character.isLetter(c)) {
                hasLetter = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            }
        }
        return hasLetter && hasDigit;
    }

    public boolean looksLikeHighEntropyToken(String token) {
        if (!config.isHighEntropyEnabled()) {
            return false;
        }
        if (token == null) {
            return false;
        }
        String t = token.trim();
        if (t.length() < config.getHighEntropyMinLength() || t.length() > config.getMaxValueLength()) {
            return false;
        }
        if ("null".equalsIgnoreCase(t)) {
            return false;
        }
        if (t.contains("://")) {
            return false;
        }
        if (t.startsWith("data:image") || t.contains("base64")) {
            return false;
        }
        if (looksLikeUuid(t)) {
            return false;
        }
        if (looksLikeHex(t)) {
            return false;
        }
        if (looksLikeUserAgentSegment(t)) {
            return false;
        }
        if (config.isHighEntropyRequireUpperLowerDigit() && !hasUpperLowerDigit(t)) {
            return false;
        }
        double entropy = shannonEntropy(t);
        return entropy >= config.getHighEntropyThreshold();
    }

    private boolean hasUpperLowerDigit(String s) {
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            }
        }
        return upper && lower && digit;
    }

    private boolean looksLikeHex(String s) {
        String t = s.toLowerCase(Locale.ROOT);
        int len = t.length();
        if (!(len == 32 || len == 40 || len == 64)) {
            return false;
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private boolean looksLikeUuid(String s) {
        if (s.length() != 36) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') {
                    return false;
                }
                continue;
            }
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private boolean looksLikeUserAgentSegment(String s) {
        int slash = s.indexOf('/');
        if (slash <= 0 || slash >= s.length() - 1) {
            return false;
        }
        String left = s.substring(0, slash);
        String right = s.substring(slash + 1);
        if (!left.chars().allMatch(Character::isLetter)) {
            return false;
        }
        boolean hasDigit = false;
        for (int i = 0; i < right.length(); i++) {
            char c = right.charAt(i);
            if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (c != '.' && c != '_') {
                return false;
            }
        }
        return hasDigit;
    }

    private double shannonEntropy(String s) {
        int[] counts = new int[128];
        int otherCount = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                counts[c]++;
            } else {
                otherCount++;
            }
        }
        double len = s.length();
        double ent = 0.0d;
        for (int i = 0; i < counts.length; i++) {
            if (counts[i] == 0) {
                continue;
            }
            double p = counts[i] / len;
            ent -= p * (Math.log(p) / Math.log(2));
        }
        if (otherCount > 0) {
            double p = otherCount / len;
            ent -= p * (Math.log(p) / Math.log(2));
        }
        return ent;
    }
}

