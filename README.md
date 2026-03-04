# SecureLog ECC

SecureLog ECC 是基于国密算法的日志安全组件，能够在保持原有日志输出链路不变的前提下，对日志中的敏感信息进行"结构化优先脱敏"，并将原始敏感值加密为 `SECURE_DATA` 随日志一起落盘，便于后续审计回溯与离线解密。

本仓库包含组件本体（`SecureLog-ECC`）以及 Logback、Log4j2、Log4j1 bridge 的示例工程。

> 💡 **AI 辅助开发说明**：本项目在开发过程中使用了 AI 辅助工具进行代码生成和优化，但所有核心算法和架构设计均由人工审核和验证确保正确性。

## 核心能力

- **结构化优先脱敏**：支持 JSON、SQL 参数、URL query、querystring、key/value 等多种格式，纯文本作为兜底方案
- **国密算法支持**：采用 SM2（加密 SM4 密钥）+ SM4（加密敏感数据）组合，JCE Provider 可通过配置加载（默认使用 BouncyCastle）
- **双轨密钥管理**：基于 `trace_id` 的会话密钥 + 系统级滚动密钥（按时间间隔自动更新）
- **事件上下文记录**：
  - `SECURE_DATA`：原始敏感值的加密载荷（Base64 格式）
  - `PUB_KEY_FINGERPRINT`：当前加密所用公钥的摘要（Base64 格式），用于快速定位对应的私钥

## 脱敏范围(默认配置)

- 强敏感 key：password、pwd、pass、token、access_token、clientSecret、secret、apiKey、idcard、cardNumber、jbrCardNumber、mobile、phone、tel、email、address（大小写不敏感）
- 值形态识别：手机号、身份证、邮箱、严格地址、高熵 token
- 结构化优先顺序：JSON → SQL Parameters → URL query → querystring → key/value → 纯文本兜底
- 兜底扫描范围：身份证、手机号、邮箱、严格地址（不做高熵 token 裸扫）

## 脱敏示例

```text
JSON
输入：{"password":"123456","mobile":"13800138000","token":"AbCdef1234567890XyZ"}
输出：{"password":"******","mobile":"138****8000","token":"AbCd****90XyZ"}

SQL Parameters
输入：Parameters: 13800138000(String), 2024-01-01(Date)
输出：Parameters: 138****8000(String), 2024-01-01(Date)

URL query
输入：/api/login?token=AbCdef1234567890XyZ&mobile=13800138000
输出：/api/login?token=AbCd****90XyZ&mobile=138****8000

querystring
输入：token=AbCdef1234567890XyZ&email=test@example.com
输出：token=AbCd****90XyZ&email=te***@example.com

key/value
输入：password=123456 token: AbCdef1234567890XyZ
输出：password=****** token: AbCd****90XyZ

纯文本
输入：用户手机号13800138000，身份证11010519491231002X
输出：用户手机号138****8000，身份证110105********002X
```

## 目录结构

- `SecureLog-ECC/`：组件本体（打包产物 `team.frog:securelog-ecc`）
- `logback-only-project/`：Logback 示例工程（含 CLI 入口）
- `log4j2-only-project/`：Log4j2 示例工程
- `log4j1-bridge-project/`：Log4j1 → Log4j2 bridge 示例工程
- `项目技术文档.md`：更完整的设计与实现说明

## 快速开始

### 1. 引入依赖（Maven）

接入工程需要自行提供日志框架与密码学 Provider 依赖（本组件在 `SecureLog-ECC/pom.xml` 中将 `slf4j/jackson/logback/log4j2` 设为 `provided`）。

```xml
<dependency>
  <groupId>team.frog</groupId>
  <artifactId>securelog-ecc</artifactId>
  <version>${securelog-ecc.version}</version>
</dependency>

<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcprov-jdk15on</artifactId>
  <version>1.70</version>
</dependency>

<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.15.4</version>
</dependency>
```

根据你的工程选型，选择引入以下日志框架依赖之一：

- **Logback**：`ch.qos.logback:logback-classic`
- **Log4j2**：`org.apache.logging.log4j:log4j-api`、`org.apache.logging.log4j:log4j-core`（如需通过 SLF4J 使用：`org.apache.logging.log4j:log4j-slf4j-impl`）

### 2. 配置 `securelog-ecc.properties`

在接入工程的 classpath（例如 `src/main/resources` 目录）下创建 `securelog-ecc.properties` 文件，最少需要配置以下内容：

```properties
ecc.public.key=<SM2公钥X509编码的Base64>
ecc.crypto.provider=org.bouncycastle.jce.provider.BouncyCastleProvider
```

常用可选配置项（均有默认值）：

```properties
# MDC 键名
mdc.secure.data.key=SECURE_DATA
mdc.pub.key.fingerprint.key=PUB_KEY_FINGERPRINT
mdc.trace.id.keys=trace_id,traceId,requestId,correlationId,X-Trace-Code,X-Trace-Id

# 密钥缓存（双轨）
ecc.session.key.cache.size=30000
ecc.session.key.cache.buffer.percentage=0.05
ecc.system.key.cache.size=1000
ecc.system.key.cache.buffer.percentage=0.1
ecc.system.id.change.interval.minutes=15
```

完整配置说明请参考：[securelog-ecc.properties](SecureLog-ECC/src/main/resources/securelog-ecc.properties) 和 [项目技术文档.md](项目技术文档.md)。

### 3. 配置日志框架接入

#### 3.1 Logback（`logback.xml`）

使用 [SecureMaskingAppender](SecureLog-ECC/src/main/java/team/frog/securelogecc/logback/SecureMaskingAppender.java) 包装目标 Appender：

```xml
<configuration>
  <appender name="FILE" class="ch.qos.logback.core.FileAppender">
    <file>out/app.log</file>
    <append>true</append>
    <encoder class="ch.qos.logback.classic.encoder.PatternLayoutEncoder">
      <pattern>%msg%n SECURE_DATA=%X{SECURE_DATA} PUB_KEY_FINGERPRINT=%X{PUB_KEY_FINGERPRINT}%n</pattern>
    </encoder>
  </appender>

  <appender name="SECURE_FILE" class="team.frog.securelogecc.logback.SecureMaskingAppender">
    <appender-ref ref="FILE"/>
  </appender>

  <root level="info">
    <appender-ref ref="SECURE_FILE"/>
  </root>
</configuration>
```

#### 3.2 Log4j2（`log4j2.xml`）

通过 [SecureMaskingPolicy](SecureLog-ECC/src/main/java/team/frog/securelogecc/log4j2/SecureMaskingPolicy.java) 注入脱敏与上下文字段，并配置 `packages` 属性以加载插件：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN" packages="team.frog.securelogecc.log4j2">
  <Appenders>
    <File name="FILE" fileName="out/app.log" append="true">
      <PatternLayout pattern="%msg%n SECURE_DATA=%X{SECURE_DATA} PUB_KEY_FINGERPRINT=%X{PUB_KEY_FINGERPRINT}%n"/>
    </File>

    <Rewrite name="SECURE_FILE">
      <SecureMaskingPolicy/>
      <AppenderRef ref="FILE"/>
    </Rewrite>
  </Appenders>

  <Loggers>
    <Root level="info">
      <AppenderRef ref="SECURE_FILE"/>
    </Root>
  </Loggers>
</Configuration>
```

### 4. 验证配置生效

打印一条包含敏感字段的日志，例如：

`password=123456&token=abc123`

期望的输出结果：

- 日志正文中的敏感值已被脱敏处理
- 同一条日志的上下文字段中会出现 `SECURE_DATA`（Base64 格式）和 `PUB_KEY_FINGERPRINT`（Base64 格式）

## 解密 `SECURE_DATA`

使用 [SecureDataDecrypter](SecureLog-ECC/src/main/java/team/frog/securelogecc/SecureDataDecrypter.java)：

```java
String plaintextJson =
  team.frog.securelogecc.SecureDataDecrypter.decryptSecureData(secureDataBase64, base64Pkcs8PrivateKey);
```

如果你需要按 `PUB_KEY_FINGERPRINT` 快速定位私钥，可使用：

- [EccCore.publicKeyFingerprint](SecureLog-ECC/src/main/java/team/frog/securelogecc/core/EccCore.java#L113-L126) 计算公钥摘要（Base64 公钥 → Base64 解码 → SHA-256 → 前 20 字节 → Base64）

组件侧会在加载公钥配置时缓存摘要（避免重复计算），见：

- [ConfigManager.getPublicKeyFingerprint](SecureLog-ECC/src/main/java/team/frog/securelogecc/manager/ConfigManager.java#L130-L143)

## CLI（生成密钥对 / 解密）

组件提供交互式 CLI：[Sm2CliApp](SecureLog-ECC/src/main/java/team/frog/securelogecc/cli/Sm2CliApp.java)。

示例工程中已提供可直接运行的入口：

- [SecureLogCli](logback-only-project/src/main/java/team/frog/securelogecc/sample/logback/SecureLogCli.java)

CLI 在输出公钥 Base64 后，会额外输出 `公钥摘要`（用于密钥识别与检索）。

## 版本历史

### 近期变更（未发布）

- 无

### v1.0.3（当前版本）

- JSON 字符串替换定位兼容性问题
- 配置加载优先从文件系统，增加脱敏处理器成功创建提示

### v1.0.2

- 配置错误时增加错误日志提醒与输出
- 生成密钥对时公钥、私钥、公钥摘要合并保存
- 公钥摘要输出与指纹计算复用，并贯通 Logback/Log4j2 的 MDC 写入

### v1.0.1

- 新增控制台工具：生成公私钥与 SECURE_DATA 解密
- 配置加载优先从文件系统，创建脱敏处理器成功提示

### v1.0.0

- 初始版本发布
- 支持双轨密钥管理
- 基于ConcurrentHashMap + ConcurrentLinkedQueue的缓存优化
- 完整的配置管理系统

## 本仓库构建与运行

### 构建组件本体

```bash
mvn -f SecureLog-ECC/pom.xml test
```

如果需要让示例工程引用本地构建的组件版本：

```bash
mvn -f SecureLog-ECC/pom.xml install
```

### 运行示例

- Logback benchmark：见 [LogbackFileBenchmark](logback-only-project/src/main/java/team/frog/securelogecc/sample/logback/LogbackFileBenchmark.java)
- Log4j2 benchmark：见 [Log4j2FileBenchmark](log4j2-only-project/src/main/java/team/frog/securelogecc/sample/log4j2/Log4j2FileBenchmark.java)

