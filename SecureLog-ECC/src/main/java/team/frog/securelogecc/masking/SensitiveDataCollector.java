package team.frog.securelogecc.masking;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

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
