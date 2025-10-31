# tls-key-format

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com)
[![Coverage Status](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com)

[English](README.md) | [中文](README.zh-CN.md)

一个用于处理TLS密钥格式转换的PHP库，支持PEM和DER格式之间的转换。

## 特性

- 支持PEM和DER格式之间的转换
- 验证PEM和DER格式数据的有效性
- 从PEM文件中提取密钥和证书信息
- 处理证书和私钥
- 完善的异常处理机制

## 安装

```bash
composer require tourze/tls-key-format
```

## 使用方法

### 基本用法

```php
<?php
use Tourze\TLSKeyFormat\PemDerFormat;
use Tourze\TLSKeyFormat\KeyHandler;
use Tourze\TLSKeyFormat\CertificateHandler;

// 初始化格式处理器
$formatter = new PemDerFormat();

// PEM转DER
$pemData = file_get_contents('certificate.pem');
$derData = $formatter->pemToDer($pemData);

// DER转PEM
$pemData = $formatter->derToPem($derData, 'CERTIFICATE');

// 验证格式
if ($formatter->isValidPem($pemData)) {
    echo "有效的PEM格式\n";
}

if ($formatter->isValidDer($derData)) {
    echo "有效的DER格式\n";
}

// 从PEM中提取信息
$info = $formatter->extractFromPem($pemData);
echo "类型: " . $info['type'] . "\n";
```

### 密钥处理

```php
<?php
use Tourze\TLSKeyFormat\KeyHandler;

$keyHandler = new KeyHandler();

// 生成新的密钥对
$keyPair = $keyHandler->generateKeyPair();

// 使用密钥
$privateKey = $keyPair['private'];
$publicKey = $keyPair['public'];
```

### 证书处理

```php
<?php
use Tourze\TLSKeyFormat\CertificateHandler;

$certHandler = new CertificateHandler();

// 解析证书
$certInfo = $certHandler->parseCertificate($pemData);

// 验证证书
if ($certHandler->validateCertificate($pemData)) {
    echo "证书有效\n";
}
```

## 配置

无需配置，库可以直接使用默认设置。

## 示例

### 完整示例

```php
<?php
require_once 'vendor/autoload.php';

use Tourze\TLSKeyFormat\PemDerFormat;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;

try {
    $formatter = new PemDerFormat();
    
    // 加载PEM证书
    $pemData = file_get_contents('example.pem');
    
    // 转换为DER
    $derData = $formatter->pemToDer($pemData);
    
    // 转换回PEM
    $pemResult = $formatter->derToPem($derData, 'CERTIFICATE');
    
    // 提取信息
    $info = $formatter->extractFromPem($pemData);
    
    echo "证书类型: " . $info['type'] . "\n";
    echo "数据长度: " . strlen($info['data']) . " 字节\n";
    
} catch (KeyFormatException $e) {
    echo "错误: " . $e->getMessage() . "\n";
}
```

## 参考文档

- [示例链接](https://example.com)

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。
