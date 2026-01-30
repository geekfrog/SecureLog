/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 纯文本兜底脱敏器。
 *
 * <p>当结构化解析（JSON / querystring / key-value / SQL Parameters）未命中或不适用时，
 * 该组件会对文本进行有限范围的正则扫描，用于覆盖常见的个人敏感信息。</p>
 *
 * <p>默认覆盖范围：
 * <ul>
 *   <li>身份证</li>
 *   <li>手机号</li>
 *   <li>邮箱</li>
 *   <li>严格地址（通过 region/detail 两阶段关键字约束，降低误报）</li>
 * </ul>
 * </p>
 *
 * <p>注意：兜底阶段不会做高熵 token 裸扫，以降低误报与性能开销。</p>
 */
public class PlainTextFallbackMasker {
    private final StructuredMaskingConfig config;
    private final MaskingRules rules;

    private final Pattern idCardFind = Pattern.compile("(?<![0-9A-Za-z])([1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx])(?![0-9A-Za-z])");
    private final Pattern mobileFind = Pattern.compile("(?<!\\d)(?:\\+?86[-\\s]?)?(1\\d{10})(?!\\d)");
    private final Pattern emailFind = Pattern.compile("(?i)(?<![A-Z0-9._%+-])([A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\\.[A-Z]{2,})(?![A-Z0-9._%+-])");
    private final Pattern addressCandidate = Pattern.compile("([\\u4e00-\\u9fa5\\d\\-#]{2,120}(?:省|市|区|县)[\\u4e00-\\u9fa5\\d\\-#]{0,120})");

    public PlainTextFallbackMasker(StructuredMaskingConfig config, MaskingRules rules) {
        this.config = config;
        this.rules = rules;
    }

    /**
     * 纯文本兜底脱敏（结构化解析失败或未命中时才使用）。
     *
     * <p>限定范围：
     * <ul>
     *   <li>身份证</li>
     *   <li>手机号</li>
     *   <li>邮箱</li>
     *   <li>严格地址（两阶段命中）</li>
     * </ul>
     * </p>
     *
     * <p>注意：不会做高熵 token 裸扫；空值（null/""/"null"）忽略。</p>
     */
    public String maskPlainText(String message, SensitiveDataCollector collector) {
        if (!config.isFallbackEnabled()) {
            return message;
        }
        if (message == null || message.isEmpty()) {
            return message;
        }
        List<Replacement> reps = new ArrayList<>();
        collectReplacements(reps, collector, message, idCardFind, "idcard", rules::maskIdCard);
        collectReplacements(reps, collector, message, mobileFind, "mobile", rules::maskPhone);
        collectReplacements(reps, collector, message, emailFind, "email", rules::maskEmail);
        collectReplacements(reps, collector, message, addressCandidate, "address", rules::maskAddress);
        reps.sort(Comparator.comparingInt((Replacement r) -> r.start).reversed());
        String out = message;
        for (Replacement r : reps) {
            out = out.substring(0, r.start) + r.replacement + out.substring(r.end);
        }
        return out;
    }

    private void collectReplacements(List<Replacement> reps, SensitiveDataCollector collector, String message, Pattern pattern, String key, Masker masker) {
        Matcher m = pattern.matcher(message);
        while (m.find()) {
            String value = m.group(1);
            if (value == null) {
                continue;
            }
            if (rules.isEmptyLike(value)) {
                continue;
            }
            if (value.length() > config.getMaxValueLength()) {
                continue;
            }
            if ("address".equals(key) && !rules.isStrictAddress(value)) {
                continue;
            }
            collector.put(key, value);
            reps.add(new Replacement(m.start(1), m.end(1), masker.mask(value)));
        }
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

    private interface Masker {
        String mask(String value);
    }
}

