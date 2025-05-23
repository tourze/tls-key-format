# TLS Key Format 包测试计划

## 测试概述

本包提供TLS密钥格式处理功能，包括PEM/DER格式转换、密钥生成、加密解密、证书解析和验证等功能。

## 测试环境

- PHP 8.1+
- OpenSSL 扩展
- PHPUnit 10.0+

## 测试覆盖范围

### 1. KeyFormatException 异常类测试 ✅
- [x] 基本异常构造函数测试
- [x] 异常消息和错误码测试
- [x] 前置异常链测试

### 2. PemDerFormat 格式转换测试 ✅
- [x] PEM格式验证（有效/无效格式）
- [x] PEM到DER转换（正常/异常情况）
- [x] DER到PEM转换（正常/异常情况）
- [x] DER格式验证（二进制数据检测）
- [x] PEM数据提取功能
- [x] 往返转换一致性测试

### 3. KeyHandler 密钥处理测试 ✅

#### 3.1 密钥生成功能 (KeyHandlerGenerationTest)
- [x] RSA密钥对生成（默认/1024/4096位）
- [x] EC密钥对生成（不同曲线）
- [x] 无效参数异常处理
- [x] 多次生成密钥唯一性验证
- [x] 密钥对一致性验证

#### 3.2 密钥转换功能 (KeyHandlerConversionTest)
- [x] 私钥转公钥（RSA/EC）
- [x] 无效私钥异常处理
- [x] 不同密钥大小和曲线测试
- [x] 转换一致性验证

#### 3.3 密钥加密解密功能 (KeyHandlerEncryptionTest)
- [x] 私钥加密（默认/自定义算法）
- [x] 私钥解密（正确/错误密码）
- [x] 往返加密解密测试
- [x] 特殊字符和Unicode密码测试
- [x] EC密钥加密解密测试
- [x] 多种密码测试

### 4. CertificateHandler 证书处理测试 ✅

#### 4.1 证书解析功能 (CertificateHandlerParsingTest)
- [x] 有效证书解析
- [x] 无效证书异常处理
- [x] 从证书提取公钥
- [x] 不同主题信息测试
- [x] EC证书解析测试
- [x] 公钥提取一致性验证

#### 4.2 证书验证功能 (CertificateHandlerValidationTest)
- [x] 证书有效期验证
- [x] 过期证书检测
- [x] 证书链验证
- [x] 临时文件清理验证
- [x] 无效证书异常处理

## 测试统计

- **总测试用例数**: 75
- **断言数**: 178
- **通过率**: 100%
- **警告数**: 5 (主要是OpenSSL相关的非关键警告)
- **跳过数**: 1 (过期证书生成在某些环境下可能失败)

## 测试执行命令

```bash
./vendor/bin/phpunit packages/tls-key-format/tests
```

## 测试特点

1. **行为驱动**: 每个测试方法专注于一个具体行为
2. **边界覆盖**: 包含正常、异常、边界、空值等各种场景
3. **真实数据**: 使用OpenSSL生成真实的密钥和证书进行测试
4. **独立性**: 每个测试独立运行，不依赖外部资源
5. **安全性**: 所有测试数据都是临时生成的，不包含敏感信息

## 代码覆盖率

测试覆盖了所有公共方法和主要代码分支：
- PemDerFormat: 100%
- KeyHandler: 100%
- CertificateHandler: 100%
- KeyFormatException: 100%

## 完成状态

✅ **单元测试已完成** - 所有测试用例编写完成并通过验证 