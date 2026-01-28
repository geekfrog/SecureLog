package team.frog.securelogecc.masking;

import java.util.ArrayList;
import java.util.List;

public class SqlParametersMasker {
    private final MaskingRules rules;

    public SqlParametersMasker(MaskingRules rules) {
        this.rules = rules;
    }

    /**
     * 脱敏 MyBatis 等框架输出的 SQL Parameters 日志。
     *
     * <p>识别形态："... Parameters: v1(String), v2(Integer), ..."</p>
     * <p>处理策略：
     * <ul>
     *   <li>仅对 (String) 的 value 处理</li>
     *   <li>对所有 String 参数都进行脱敏，以防参数中包含密码/手机号/证件号等</li>
     *   <li>优先按值形态脱敏：身份证/手机号/邮箱/严格地址；否则使用通用掩码 "***"</li>
     * </ul>
     * </p>
     */
    public String maskSqlParametersLine(String message, SensitiveDataCollector collector) {
        if (message == null || message.isEmpty()) {
            return message;
        }
        int idx = indexOfIgnoreCase(message, "Parameters:");
        if (idx < 0) {
            return message;
        }

        int start = idx + "Parameters:".length();
        if (start >= message.length()) {
            return message;
        }

        String prefix = message.substring(0, start);
        String rest = message.substring(start);
        List<String> parts = splitParametersList(rest);
        if (parts.isEmpty()) {
            return message;
        }

        List<String> maskedParts = new ArrayList<>(parts.size());
        for (int i = 0; i < parts.size(); i++) {
            String part = parts.get(i).trim();
            int lpar = part.lastIndexOf('(');
            int rpar = part.endsWith(")") ? part.length() - 1 : -1;
            if (lpar > 0 && rpar > lpar) {
                String value = part.substring(0, lpar).trim();
                String type = part.substring(lpar + 1, rpar).trim();
                String pathKey = "sqlParameters[" + i + "]";
                if ("String".equalsIgnoreCase(type)) {
                    String masked = maskSqlStringValue(value, pathKey, collector);
                    maskedParts.add(masked + "(" + type + ")");
                } else {
                    maskedParts.add(part);
                }
            } else {
                maskedParts.add(part);
            }
        }

        return prefix + " " + String.join(", ", maskedParts);
    }

    private String maskSqlStringValue(String value, String pathKey, SensitiveDataCollector collector) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        if (rules.isEmptyLike(value)) {
            return value;
        }
        collector.put(pathKey, value);
        if (rules.isIdCard(value)) {
            return rules.maskIdCard(value);
        }
        if (rules.isPhoneOrTel(value)) {
            return rules.maskPhone(value);
        }
        if (rules.isEmail(value)) {
            return rules.maskEmail(value);
        }
        if (rules.isStrictAddress(value)) {
            return rules.maskAddress(value);
        }
        return "***";
    }

    private int indexOfIgnoreCase(String s, String needle) {
        return s.toLowerCase().indexOf(needle.toLowerCase());
    }

    private List<String> splitParametersList(String s) {
        List<String> parts = new ArrayList<>();
        StringBuilder sb = new StringBuilder(s.length());
        int parenDepth = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '(') {
                parenDepth++;
                sb.append(ch);
                continue;
            }
            if (ch == ')') {
                if (parenDepth > 0) {
                    parenDepth--;
                }
                sb.append(ch);
                continue;
            }
            if (parenDepth == 0 && ch == ',') {
                String part = sb.toString().trim();
                if (!part.isEmpty()) {
                    parts.add(part);
                }
                sb.setLength(0);
                continue;
            }
            sb.append(ch);
        }
        String tail = sb.toString().trim();
        if (!tail.isEmpty()) {
            parts.add(tail);
        }
        return parts;
    }
}

