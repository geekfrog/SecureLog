/*
 * Copyright (c) 2026 宅宅蛙(GeekFrog)
 * SPDX-License-Identifier: MIT
 */
package team.frog.securelogecc.sample.logback;

import ch.qos.logback.classic.LoggerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class LogbackFileBenchmark {
    private static final Logger logger = LoggerFactory.getLogger("perf.file");

    public static void main(String[] args) throws Exception {
        String inputPath = args != null && args.length > 0 ? args[0] : "e:\\trae\\LogSecure\\logData.txt";
        int warmupMessages = args != null && args.length > 1 ? Integer.parseInt(args[1]) : 20000;
        int measureMessages = args != null && args.length > 2 ? Integer.parseInt(args[2]) : 200000;
        int traceIdChangeInterval = args != null && args.length > 3 ? Integer.parseInt(args[3]) : 10;
        int traceIdCardinality = args != null && args.length > 4 ? Integer.parseInt(args[4]) : 1000;

        List<String> lines = readNonEmptyLines(inputPath);
        if (lines.isEmpty()) {
            System.out.println("NO_INPUT_LINES");
            return;
        }

        ensureParentDirExists("out/perf-secure.log");

        for (int i = 0; i < warmupMessages; i++) {
            updateTraceId(i, traceIdChangeInterval, traceIdCardinality);
            logger.info(lines.get(i % lines.size()));
        }

        long t0 = System.nanoTime();
        for (int i = 0; i < measureMessages; i++) {
            updateTraceId(i, traceIdChangeInterval, traceIdCardinality);
            logger.info(lines.get(i % lines.size()));
        }
        long t1 = System.nanoTime();

        MDC.remove("trace_id");
        shutdownLogback();
        long t2 = System.nanoTime();

        double loopSeconds = (t1 - t0) / 1_000_000_000.0d;
        double totalSeconds = (t2 - t0) / 1_000_000_000.0d;

        File out = new File("out/perf-secure.log");

        System.out.println("ENGINE=logback");
        System.out.println("INPUT_FILE=" + inputPath);
        System.out.println("INPUT_LINES=" + lines.size());
        System.out.println("WARMUP_MESSAGES=" + warmupMessages);
        System.out.println("MEASURE_MESSAGES=" + measureMessages);
        System.out.println("OUT_FILE=" + out.getAbsolutePath());
        System.out.println("OUT_BYTES=" + (out.isFile() ? out.length() : -1L));
        System.out.println("TRACE_ID_CHANGE_INTERVAL=" + traceIdChangeInterval);
        System.out.println("TRACE_ID_CARDINALITY=" + traceIdCardinality);
        System.out.println("LOOP_ONLY_SECONDS=" + loopSeconds);
        System.out.println("TOTAL_SECONDS=" + totalSeconds);
        System.out.println("THROUGHPUT_MSG_PER_SEC_LOOP_ONLY=" + (measureMessages / loopSeconds));
        System.out.println("THROUGHPUT_MSG_PER_SEC_TOTAL=" + (measureMessages / totalSeconds));
        System.out.println("AVG_US_PER_MSG_LOOP_ONLY=" + ((loopSeconds * 1_000_000.0d) / measureMessages));
        System.out.println("AVG_US_PER_MSG_TOTAL=" + ((totalSeconds * 1_000_000.0d) / measureMessages));
    }

    private static void shutdownLogback() {
        try {
            LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
            ctx.stop();
        } catch (Exception ignored) {
        }
    }

    private static void ensureParentDirExists(String filePath) {
        File f = new File(filePath);
        File p = f.getParentFile();
        if (p != null && !p.exists()) {
            p.mkdirs();
        }
    }

    private static List<String> readNonEmptyLines(String path) throws Exception {
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    lines.add(line);
                }
            }
        }
        return lines;
    }

    private static void updateTraceId(int index, int changeInterval, int cardinality) {
        if (changeInterval <= 0 || cardinality <= 0) {
            return;
        }
        if (index % changeInterval == 0) {
            int bucket = index % cardinality;
            MDC.put("trace_id", "trace_" + bucket);
        }
    }
}
