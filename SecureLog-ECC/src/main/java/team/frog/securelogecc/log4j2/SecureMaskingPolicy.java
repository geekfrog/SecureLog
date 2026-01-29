package team.frog.securelogecc.log4j2;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.rewrite.RewritePolicy;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.util.ReadOnlyStringMap;
import org.apache.logging.log4j.util.SortedArrayStringMap;
import org.apache.logging.log4j.util.StringMap;
import org.slf4j.MDC;
import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.manager.ConfigManager;
import team.frog.securelogecc.masking.LogMaskingProcessor;

import java.util.HashMap;
import java.util.Map;

/**
 * Log4j2 场景的日志脱敏 + 敏感数据加密 RewritePolicy。
 *
 * <p>该策略通常配合 Log4j2 的 RewriteAppender 使用：对原始 {@link LogEvent} 的 message 做脱敏，
 * 并在命中敏感值时向 contextData 写入 SECURE_DATA（默认 key 为 {@code SECURE_DATA}）。</p>
 *
 * <p>traceId 绑定：
 * 支持从事件 contextData 中读取多个 traceId key（见 {@link ConfigConstants#MDC_TRACE_ID_KEYS}），在处理期间写入 SLF4J MDC，
 * 使加密侧可基于 traceId 生成/复用会话密钥；处理结束后恢复原 MDC，避免污染调用线程的上下文。</p>
 */
@Plugin(name = "SecureMaskingPolicy", category = "Core", elementType = "rewritePolicy", printObject = true)
public class SecureMaskingPolicy implements RewritePolicy {
    private final LogMaskingProcessor maskingProcessor = new LogMaskingProcessor();
    private volatile String secureDataKey;
    private volatile String[] traceIdKeys;

    @PluginFactory
    public static SecureMaskingPolicy createPolicy() {
        return new SecureMaskingPolicy();
    }

    @Override
    public LogEvent rewrite(LogEvent source) {
        if (source == null) {
            return null;
        }

        String key = secureDataKey;
        if (key == null) {
            key = ConfigManager.getInstance().getProperty(
                    ConfigConstants.MDC_SECURE_DATA_KEY,
                    ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY
            );
            secureDataKey = key;
            String traceIdKeysConfig = ConfigManager.getInstance().getProperty(
                    ConfigConstants.MDC_TRACE_ID_KEYS,
                    ConfigConstants.DEFAULT_MDC_TRACE_ID_KEYS
            );
            traceIdKeys = splitKeys(traceIdKeysConfig);
        }

        ReadOnlyStringMap contextData = source.getContextData();
        Map<String, String> previousMdc = bindTraceIdToMdc(contextData);
        LogMaskingProcessor.ProcessResult result;
        try {
            result = maskingProcessor.processLogResult(source.getMessage().getFormattedMessage());
        } finally {
            restoreTraceIdMdc(previousMdc);
        }
        String maskedMessage = result.getDesensitizedMessage();
        String secureData = result.getSecureData();

        Log4jLogEvent.Builder builder = new Log4jLogEvent.Builder(source);
        builder.setMessage(new SimpleMessage(maskedMessage));

        boolean hasSecureData = secureData != null && !secureData.isEmpty();
        if (hasSecureData) {
            StringMap newContextData = new SortedArrayStringMap(source.getContextData());
            newContextData.putValue(key, secureData);
            builder.setContextData(newContextData);
        } else {
            Object existingSecure = contextData.getValue(key);
            if (existingSecure != null) {
                StringMap newContextData = new SortedArrayStringMap(contextData);
                newContextData.remove(key);
                builder.setContextData(newContextData);
            }
        }

        return builder.build();
    }

    private Map<String, String> bindTraceIdToMdc(ReadOnlyStringMap contextData) {
        if (contextData == null || traceIdKeys == null || traceIdKeys.length == 0) {
            return null;
        }
        Map<String, String> previous = null;
        for (String key : traceIdKeys) {
            if (key == null || key.isEmpty()) {
                continue;
            }
            Object valueObj = contextData.getValue(key);
            if (valueObj == null) {
                continue;
            }
            String value = valueObj.toString();
            if (value.isEmpty()) {
                continue;
            }
            if (previous == null) {
                previous = new HashMap<>();
            }
            previous.put(key, MDC.get(key));
            MDC.put(key, value);
        }
        return previous;
    }

    private void restoreTraceIdMdc(Map<String, String> previous) {
        if (previous == null || previous.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : previous.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (value == null || value.isEmpty()) {
                MDC.remove(key);
            } else {
                MDC.put(key, value);
            }
        }
    }

    private String[] splitKeys(String keysConfig) {
        if (keysConfig == null || keysConfig.trim().isEmpty()) {
            return new String[0];
        }
        return keysConfig.split("\\s*,\\s*");
    }
}
