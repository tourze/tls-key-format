# tls-key-format

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com)
[![Coverage Status](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com)

[English](README.md) | [中文](README.zh-CN.md)

A PHP library for handling TLS key format conversions between PEM and DER formats.

## Features

- Convert between PEM and DER formats
- Validate PEM and DER format data
- Extract key and certificate information from PEM files
- Handle certificates and private keys
- Comprehensive error handling with exceptions

## Installation

```bash
composer require tourze/tls-key-format
```

## Usage

### Basic Usage

```php
<?php
use Tourze\TLSKeyFormat\PemDerFormat;
use Tourze\TLSKeyFormat\KeyHandler;
use Tourze\TLSKeyFormat\CertificateHandler;

// Initialize the format handler
$formatter = new PemDerFormat();

// Convert PEM to DER
$pemData = file_get_contents('certificate.pem');
$derData = $formatter->pemToDer($pemData);

// Convert DER to PEM
$pemData = $formatter->derToPem($derData, 'CERTIFICATE');

// Validate formats
if ($formatter->isValidPem($pemData)) {
    echo "Valid PEM format\n";
}

if ($formatter->isValidDer($derData)) {
    echo "Valid DER format\n";
}

// Extract information from PEM
$info = $formatter->extractFromPem($pemData);
echo "Type: " . $info['type'] . "\n";
```

### Key Handling

```php
<?php
use Tourze\TLSKeyFormat\KeyHandler;

$keyHandler = new KeyHandler();

// Generate a new key pair
$keyPair = $keyHandler->generateKeyPair();

// Work with keys
$privateKey = $keyPair['private'];
$publicKey = $keyPair['public'];
```

### Certificate Handling

```php
<?php
use Tourze\TLSKeyFormat\CertificateHandler;

$certHandler = new CertificateHandler();

// Parse certificate
$certInfo = $certHandler->parseCertificate($pemData);

// Validate certificate
if ($certHandler->validateCertificate($pemData)) {
    echo "Certificate is valid\n";
}
```

## Configuration

No configuration is required. The library works out of the box with default settings.

## Examples

### Complete Example

```php
<?php
require_once 'vendor/autoload.php';

use Tourze\TLSKeyFormat\PemDerFormat;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;

try {
    $formatter = new PemDerFormat();
    
    // Load a PEM certificate
    $pemData = file_get_contents('example.pem');
    
    // Convert to DER
    $derData = $formatter->pemToDer($pemData);
    
    // Convert back to PEM
    $pemResult = $formatter->derToPem($derData, 'CERTIFICATE');
    
    // Extract information
    $info = $formatter->extractFromPem($pemData);
    
    echo "Certificate type: " . $info['type'] . "\n";
    echo "Data length: " . strlen($info['data']) . " bytes\n";
    
} catch (KeyFormatException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## References

- [Example Link](https://example.com)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
