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

public class SecureMaskingAppender extends UnsynchronizedAppenderBase<ILoggingEvent> implements AppenderAttachable<ILoggingEvent> {
    private final AppenderAttachableImpl<ILoggingEvent> aai = new AppenderAttachableImpl<>();
    private final LogMaskingProcessor maskingProcessor = new LogMaskingProcessor();
    private volatile String secureDataKey = ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY;
    private volatile String[] traceIdKeys;

    @Override
    public void start() {
        this.secureDataKey = ConfigManager.getInstance().getProperty(
                ConfigConstants.MDC_SECURE_DATA_KEY,
                ConfigConstants.DEFAULT_MDC_SECURE_DATA_KEY
        );
        String traceIdKeysConfig = ConfigManager.getInstance().getProperty(
                ConfigConstants.MDC_TRACE_ID_KEYS,
                ConfigConstants.DEFAULT_MDC_TRACE_ID_KEYS
        );
        this.traceIdKeys = splitKeys(traceIdKeysConfig);
        super.start();
    }

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
                maskedEvent.setMDCPropertyMap(appendSecureData(mdcPropertyMap, secureData));
            } else if (secureData != null && !secureData.isEmpty()) {
                Map<String, String> newMdc = new HashMap<>();
                newMdc.put(this.secureDataKey, secureData);
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

    private Map<String, String> appendSecureData(Map<String, String> originalMdc, String secureData) {
        Map<String, String> map = new HashMap<>(originalMdc.size() + 1);
        map.putAll(originalMdc);
        boolean hasSecureData = secureData != null && !secureData.isEmpty();
        if (hasSecureData) {
            map.put(this.secureDataKey, secureData);
        } else {
            map.remove(this.secureDataKey);
        }
        return map;
    }

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

    @Override
    public void addAppender(Appender<ILoggingEvent> newAppender) {
        aai.addAppender(newAppender);
    }

    @Override
    public Iterator<Appender<ILoggingEvent>> iteratorForAppenders() {
        return aai.iteratorForAppenders();
    }

    @Override
    public Appender<ILoggingEvent> getAppender(String name) {
        return aai.getAppender(name);
    }

    @Override
    public boolean isAttached(Appender<ILoggingEvent> appender) {
        return aai.isAttached(appender);
    }

    @Override
    public void detachAndStopAllAppenders() {
        aai.detachAndStopAllAppenders();
    }

    @Override
    public boolean detachAppender(Appender<ILoggingEvent> appender) {
        return aai.detachAppender(appender);
    }

    @Override
    public boolean detachAppender(String name) {
        return aai.detachAppender(name);
    }
}
