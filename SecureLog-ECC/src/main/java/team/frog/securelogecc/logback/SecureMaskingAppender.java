/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.logback;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggerContextVO;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.UnsynchronizedAppenderBase;
import ch.qos.logback.core.spi.AppenderAttachable;
import ch.qos.logback.core.spi.AppenderAttachableImpl;
import org.slf4j.MDC;
import team.frog.securelogecc.config.ConfigConstants;
import team.frog.securelogecc.manager.ConfigManager;
import team.frog.securelogecc.masking.LogMaskingProcessor;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Logback 场景的日志脱敏 + 敏感数据加密 Appender。
 *
 * <p>核心职责：
 * <ul>
 *   <li>对日志 message 做结构化优先脱敏（JSON / querystring / SQL Parameters / key-value / 纯文本兜底）</li>
 *   <li>将命中的“原始敏感值”加密为 SECURE_DATA，并写入 MDC（默认 key 为 {@code SECURE_DATA}）</li>
 *   <li>透传原日志事件的关键信息（loggerName、level、marker、callerData、throwable 等）并转发到下游真实 Appender</li>
 * </ul>
 * </p>
 *
 * <p>traceId 绑定：
 * 组件可配置多个 traceId key（见 {@link ConfigConstants#MDC_TRACE_ID_KEYS}），Appender 会在处理期间将事件中的 traceId
 * 写入当前线程 MDC，使加密侧可基于 traceId 生成/复用会话密钥；处理结束后恢复原 MDC，避免污染业务线程上下文。</p>
 */
public class SecureMaskingAppender extends UnsynchronizedAppenderBase<ILoggingEvent> implements AppenderAttachable<ILoggingEvent> {
    private final AppenderAttachableImpl<ILoggingEvent> aai = new AppenderAttachableImpl<>();
    private final LogMaskingProcessor maskingProcessor = new LogMaskingProcessor();
    private volatile String secureDataKey = ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY;
    private volatile String publicKeyFingerprintKey = ConfigConstants.DEFAULT_MDC_PUB_KEY_FINGERPRINT;
    private volatile String[] traceIdKeys;

    /**
     * 初始化配置并启动 Appender。
     */
    @Override
    public void start() {
        this.secureDataKey = ConfigManager.getInstance().getProperty(
                ConfigConstants.MDC_SECURE_DATA_KEY,
                ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY
        );
        this.publicKeyFingerprintKey = ConfigManager.getInstance().getProperty(
                ConfigConstants.MDC_PUB_KEY_FINGERPRINT,
                ConfigConstants.DEFAULT_MDC_PUB_KEY_FINGERPRINT
        );
        String traceIdKeysConfig = ConfigManager.getInstance().getProperty(
                ConfigConstants.MDC_TRACE_ID_KEYS,
                ConfigConstants.DEFAULT_MDC_TRACE_ID_KEYS
        );
        this.traceIdKeys = splitKeys(traceIdKeysConfig);
        super.start();
    }

    /**
     * 处理并转发日志事件：脱敏消息，写入/移除 SECURE_DATA。
     * 处理期间临时把 traceId 写入 MDC，并在 finally 中恢复旧值。
     */
    @Override
    protected void append(ILoggingEvent eventObject) {
        if (eventObject == null) {
            return;
        }

        Map<String, String> mdcPropertyMap = eventObject.getMDCPropertyMap();
        Map<String, String> previousMdc = bindTraceIdToMdc(mdcPropertyMap);
        try {
            LogMaskingProcessor.ProcessResult result = maskingProcessor.processLogResult(eventObject.getFormattedMessage());
            String maskedMessage = result.getDesensitizedMessage();
            String secureData = result.getSecureData();
            String publicKeyFingerprint = result.getPublicKeyFingerprint();

            LoggingEvent maskedEvent = new LoggingEvent();
            maskedEvent.setLoggerName(eventObject.getLoggerName());
            maskedEvent.setLevel(eventObject.getLevel());
            maskedEvent.setTimeStamp(eventObject.getTimeStamp());
            maskedEvent.setThreadName(eventObject.getThreadName());
            maskedEvent.setMessage(maskedMessage);
            maskedEvent.setArgumentArray(null);
            maskedEvent.setMarker(eventObject.getMarker());
            maskedEvent.setCallerData(eventObject.getCallerData());

            LoggerContextVO contextVO = eventObject.getLoggerContextVO();
            if (contextVO != null) {
                maskedEvent.setLoggerContextRemoteView(contextVO);
            }

            if (mdcPropertyMap != null && !mdcPropertyMap.isEmpty()) {
                maskedEvent.setMDCPropertyMap(appendSecureData(mdcPropertyMap, secureData, publicKeyFingerprint));
            } else if (secureData != null && !secureData.isEmpty()) {
                Map<String, String> newMdc = new HashMap<>();
                newMdc.put(this.secureDataKey, secureData);
                if (publicKeyFingerprint != null && !publicKeyFingerprint.isEmpty()) {
                    newMdc.put(this.publicKeyFingerprintKey, publicKeyFingerprint);
                }
                maskedEvent.setMDCPropertyMap(newMdc);
            }

            if (eventObject.getThrowableProxy() instanceof ThrowableProxy) {
                maskedEvent.setThrowableProxy((ThrowableProxy) eventObject.getThrowableProxy());
            }

            aai.appendLoopOnAppenders(maskedEvent);
        } finally {
            restoreTraceIdMdc(previousMdc);
        }
    }

    /**
     * 在事件 MDC 上追加或移除 SECURE_DATA 与公钥指纹。
     */
    private Map<String, String> appendSecureData(Map<String, String> originalMdc, String secureData, String publicKeyFingerprint) {
        Map<String, String> map = new HashMap<>(originalMdc.size() + 2);
        map.putAll(originalMdc);
        boolean hasSecureData = secureData != null && !secureData.isEmpty();
        if (hasSecureData) {
            map.put(this.secureDataKey, secureData);
            if (publicKeyFingerprint != null && !publicKeyFingerprint.isEmpty()) {
                map.put(this.publicKeyFingerprintKey, publicKeyFingerprint);
            }
        } else {
            map.remove(this.secureDataKey);
            map.remove(this.publicKeyFingerprintKey);
        }
        return map;
    }

    /**
     * 从事件 MDC 读取 traceId 并临时写入线程 MDC，返回旧值用于恢复。
     */
    private Map<String, String> bindTraceIdToMdc(Map<String, String> mdcPropertyMap) {
        if (mdcPropertyMap == null || mdcPropertyMap.isEmpty() || traceIdKeys == null || traceIdKeys.length == 0) {
            return null;
        }
        Map<String, String> previous = null;
        for (String key : traceIdKeys) {
            if (key == null || key.isEmpty()) {
                continue;
            }
            String value = mdcPropertyMap.get(key);
            if (value == null || value.isEmpty()) {
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

    /**
     * 恢复线程 MDC 中的 traceId 到处理前的状态。
     */
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

    /**
     * 添加下游 Appender。
     *
     * @param newAppender 下游 Appender
     */
    @Override
    public void addAppender(Appender<ILoggingEvent> newAppender) {
        aai.addAppender(newAppender);
    }

    /**
     * 获取已挂载 Appender 的迭代器。
     *
     * @return Appender 迭代器
     */
    @Override
    public Iterator<Appender<ILoggingEvent>> iteratorForAppenders() {
        return aai.iteratorForAppenders();
    }

    /**
     * 按名称获取 Appender。
     *
     * @param name Appender 名称
     * @return Appender 实例
     */
    @Override
    public Appender<ILoggingEvent> getAppender(String name) {
        return aai.getAppender(name);
    }

    /**
     * 判断 Appender 是否已挂载。
     *
     * @param appender Appender 实例
     * @return 是否已挂载
     */
    @Override
    public boolean isAttached(Appender<ILoggingEvent> appender) {
        return aai.isAttached(appender);
    }

    /**
     * 解除并停止所有 Appender。
     */
    @Override
    public void detachAndStopAllAppenders() {
        aai.detachAndStopAllAppenders();
    }

    /**
     * 按实例解除 Appender。
     *
     * @param appender Appender 实例
     * @return 是否成功移除
     */
    @Override
    public boolean detachAppender(Appender<ILoggingEvent> appender) {
        return aai.detachAppender(appender);
    }

    /**
     * 按名称解除 Appender。
     *
     * @param name Appender 名称
     * @return 是否成功移除
     */
    @Override
    public boolean detachAppender(String name) {
        return aai.detachAppender(name);
    }
}
