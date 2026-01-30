/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.masking;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 敏感值提取收集器。
 *
 * <p>用于在脱敏过程中记录“原始敏感值”，最终以 key-value Map 形式输出，
 * 供 {@code SecureDataBuilder} 加密并写入 SECURE_DATA。</p>
 *
 * <p>规则：
 * <ul>
 *   <li>按插入顺序保存（LinkedHashMap），便于审计回溯</li>
 *   <li>key 规范化为小写、去空白；重复 key 自动追加数字后缀避免覆盖</li>
 * </ul>
 * </p>
 */
public class SensitiveDataCollector {
    private final Map<String, String> data = new LinkedHashMap<>();

    /**
     * 记录一条敏感数据。
     *
     * <p>规则：
     * <ul>
     *   <li>key 为空直接忽略</li>
     *   <li>value 为 null 直接忽略</li>
     *   <li>key 重复不覆盖：依次生成 key1、key2...</li>
     * </ul>
     * </p>
     */
    public void put(String key, String value) {
        if (key == null || key.trim().isEmpty() || value == null) {
            return;
        }
        String normalizedKey = normalizeKey(key);
        if (normalizedKey.isEmpty()) {
            return;
        }
        if (!data.containsKey(normalizedKey)) {
            data.put(normalizedKey, value);
            return;
        }
        int idx = 1;
        while (true) {
            String candidate = normalizedKey + idx;
            if (!data.containsKey(candidate)) {
                data.put(candidate, value);
                return;
            }
            idx++;
        }
    }

    public Map<String, String> snapshot() {
        return new LinkedHashMap<>(data);
    }

    private String normalizeKey(String key) {
        String k = key.trim();
        if (k.isEmpty()) {
            return "";
        }
        k = k.replace("\"", "").replace("`", "");
        k = k.replaceAll("\\s+", "");
        return k.toLowerCase(Locale.ROOT);
    }
}
