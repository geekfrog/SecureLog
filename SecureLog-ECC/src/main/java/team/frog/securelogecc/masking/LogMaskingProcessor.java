package team.frog.securelogecc.masking;

import org.slf4j.MDC;
import team.frog.securelogecc.SecureDataBuilder;
import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.manager.ConfigManager;

import java.util.Map;

public class LogMaskingProcessor {
    private final String secureDataKey;
    private final String[] traceIdKeys;
    private final StructuredMaskingEngine maskingEngine;
    private SecureDataBuilder secureDataBuilder;

    public static class ProcessResult {
        private final String desensitizedMessage;
        private final String secureData;

        public ProcessResult(String desensitizedMessage, String secureData) {
            this.desensitizedMessage = desensitizedMessage;
            this.secureData = secureData;
        }

        public String getDesensitizedMessage() {
            return desensitizedMessage;
        }

        public String getSecureData() {
            return secureData;
        }
    }

    /**
     * 创建脱敏处理器。
     *
     * <p>处理流程：
     * <ol>
     *   <li>读取配置：敏感 key 列表、token-like key 列表、querystring/兜底开关、地址两阶段识别开关等</li>
     *   <li>构建结构化优先的脱敏引擎（JSON / querystring / SQL Parameters / 纯文本兜底）</li>
     *   <li>准备 SECURE_DATA 构建器：用于将提取到的原始敏感值加密后写入 SECURE_DATA</li>
     * </ol>
     */
    public LogMaskingProcessor() {
        ConfigManager config = ConfigManager.getInstance();
        this.secureDataKey = config.getProperty(ConfigConstants.MDC_SECURE_DATA_KEY, ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY);
        this.traceIdKeys = splitKeys(config.getProperty(ConfigConstants.MDC_TRACE_ID_KEYS, ConfigConstants.DEFAULT_MDC_TRACE_ID_KEYS));
        this.maskingEngine = new StructuredMaskingEngine(new StructuredMaskingConfig(config));
        try {
            this.secureDataBuilder = new SecureDataBuilder();
        } catch (Exception e) {
            this.secureDataBuilder = null;
        }
    }

    public String processLog(String originalMessage) {
        ProcessResult result = process(originalMessage);
        if (result.getSecureData() != null) {
            MDC.put(this.secureDataKey, result.getSecureData());
        } else {
            MDC.remove(this.secureDataKey);
        }
        return result.getDesensitizedMessage();
    }

    public ProcessResult processLogResult(String originalMessage) {
        return process(originalMessage);
    }

    /**
     * 清理 MDC 中存放的 SECURE_DATA。
     */
    public void clearSecureDataFromMdc() {
        MDC.remove(this.secureDataKey);
    }

    /**
     * 对单条日志文本进行脱敏处理，并在命中敏感值时生成 SECURE_DATA。
     *
     * <p>返回值中的 desensitizedMessage 保持“原日志格式”，只对命中的 value 做最小替换；
     * SECURE_DATA 中保存的是“原始敏感值”的加密载荷，供审计/回溯使用。</p>
     */
    private ProcessResult process(String originalMessage) {
        if (originalMessage == null || originalMessage.isEmpty()) {
            return new ProcessResult(originalMessage, null);
        }

        StructuredMaskingEngine.Result r = maskingEngine.mask(originalMessage);
        String sensitiveDataJson = convertToJson(r.getExtracted());
        String secureData = null;
        if (sensitiveDataJson != null && !sensitiveDataJson.isEmpty()) {
            secureData = buildSecureData(sensitiveDataJson, getTraceIdFromMdc());
        }
        return new ProcessResult(r.getMasked(), secureData);
    }

    private String buildSecureData(String sensitiveDataJson, String traceId) {
        try {
            if (this.secureDataBuilder == null) {
                this.secureDataBuilder = new SecureDataBuilder();
            }
            if (traceId != null && !traceId.isEmpty()) {
                return secureDataBuilder.buildSecureDataForBusinessLog(sensitiveDataJson, traceId);
            }
            return secureDataBuilder.buildSecureDataForSystemLog(sensitiveDataJson);
        } catch (Exception e) {
            return null;
        }
    }

    private String convertToJson(Map<String, String> keyValuePairs) {
        if (keyValuePairs == null || keyValuePairs.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder(keyValuePairs.size() * 32);
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, String> entry : keyValuePairs.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escapeJson(entry.getKey())).append('"').append(':').append('"').append(escapeJson(entry.getValue())).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
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

    private String getTraceIdFromMdc() {
        if (traceIdKeys == null) {
            return null;
        }
        for (String key : traceIdKeys) {
            String traceId = MDC.get(key);
            if (traceId != null && !traceId.isEmpty()) {
                return traceId;
            }
        }
        return null;
    }

    private String[] splitKeys(String keysConfig) {
        if (keysConfig == null || keysConfig.trim().isEmpty()) {
            return new String[0];
        }
        return keysConfig.split("\\s*,\\s*");
    }
}

