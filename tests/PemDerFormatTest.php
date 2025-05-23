<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\PemDerFormat;

/**
 * PemDerFormat类测试
 */
class PemDerFormatTest extends TestCase
{
    private PemDerFormat $pemDerFormat;
    
    protected function setUp(): void
    {
        $this->pemDerFormat = new PemDerFormat();
    }
    
    public function test_isValidPem_withValidPemCertificate()
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n" .
                   "MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAoMCVRl\n" .
                   "c3QgQ2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV\n" .
                   "BAoMCVRlc3QgQ2VydDBcMA0GCSqGSIb3DQEBAQUAAksAMEgCQQDTgvwjlRHZ5X2j\n" .
                   "-----END CERTIFICATE-----\n";
        
        $this->assertTrue($this->pemDerFormat->isValidPem($validPem));
    }
    
    public function test_isValidPem_withInvalidFormat()
    {
        $invalidPem = "INVALID PEM DATA";
        $this->assertFalse($this->pemDerFormat->isValidPem($invalidPem));
    }
    
    public function test_isValidPem_withMismatchedHeaders()
    {
        $mismatchedPem = "-----BEGIN CERTIFICATE-----\n" .
                        "SGVsbG8gV29ybGQ=\n" .
                        "-----END PRIVATE KEY-----\n";
        
        $this->assertFalse($this->pemDerFormat->isValidPem($mismatchedPem));
    }
    
    public function test_isValidPem_withInvalidBase64()
    {
        $invalidBase64Pem = "-----BEGIN CERTIFICATE-----\n" .
                           "This is not valid base64!@#$%\n" .
                           "-----END CERTIFICATE-----\n";
        
        $this->assertFalse($this->pemDerFormat->isValidPem($invalidBase64Pem));
    }
    
    public function test_isValidPem_withEmptyContent()
    {
        $emptyPem = "-----BEGIN CERTIFICATE-----\n" .
                   "-----END CERTIFICATE-----\n";
        
        $this->assertFalse($this->pemDerFormat->isValidPem($emptyPem));
    }
    
    public function test_pemToDer_withValidPem()
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n" .
                   "SGVsbG8gV29ybGQ=\n" .
                   "-----END CERTIFICATE-----\n";
        
        $derData = $this->pemDerFormat->pemToDer($validPem);
        $this->assertSame('Hello World', $derData);
    }
    
    public function test_pemToDer_withInvalidPem()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');
        
        $this->pemDerFormat->pemToDer('INVALID PEM');
    }
    
    public function test_pemToDer_withMismatchedHeaders()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');
        
        $mismatchedPem = "-----BEGIN CERTIFICATE-----\n" .
                        "SGVsbG8=\n" .
                        "-----END PRIVATE KEY-----\n";
        
        $this->pemDerFormat->pemToDer($mismatchedPem);
    }
    
    public function test_pemToDer_withInvalidBase64()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');
        
        $invalidBase64Pem = "-----BEGIN CERTIFICATE-----\n" .
                           "Invalid Base64!@#\n" .
                           "-----END CERTIFICATE-----\n";
        
        $this->pemDerFormat->pemToDer($invalidBase64Pem);
    }
    
    public function test_derToPem_withValidDer()
    {
        // 使用真实的二进制DER数据
        $derData = "\x30\x82\x01\x00\x02\x01\x00";
        $type = 'CERTIFICATE';
        
        $pemData = $this->pemDerFormat->derToPem($derData, $type);
        
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $pemData);
        $this->assertStringContainsString('-----END CERTIFICATE-----', $pemData);
    }
    
    public function test_derToPem_withInvalidType()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的DER格式数据');
        
        $this->pemDerFormat->derToPem('test', 'invalid-type');
    }
    
    public function test_derToPem_withEmptyType()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的DER格式数据');
        
        $this->pemDerFormat->derToPem('test', '');
    }
    
    public function test_derToPem_withInvalidDer()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的DER格式数据');
        
        // 传入明显的文本数据而非二进制数据
        $textData = 'This is clearly text, not binary DER data with enough characters to pass length check';
        $this->pemDerFormat->derToPem($textData, 'CERTIFICATE');
    }
    
    public function test_extractFromPem_withValidPem()
    {
        $validPem = "-----BEGIN PRIVATE KEY-----\n" .
                   "SGVsbG8gV29ybGQ=\n" .
                   "-----END PRIVATE KEY-----\n";
        
        $result = $this->pemDerFormat->extractFromPem($validPem);
        
        $this->assertIsArray($result);
        $this->assertArrayHasKey('type', $result);
        $this->assertArrayHasKey('data', $result);
        $this->assertSame('PRIVATE KEY', $result['type']);
        $this->assertSame('Hello World', $result['data']);
    }
    
    public function test_extractFromPem_withInvalidPem()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');
        
        $this->pemDerFormat->extractFromPem('INVALID PEM DATA');
    }
    
    public function test_isValidDer_withBinaryData()
    {
        // 创建包含控制字符的二进制数据
        $binaryData = "\x30\x82\x01\x00\x02\x01\x00";
        $this->assertTrue($this->pemDerFormat->isValidDer($binaryData));
    }
    
    public function test_isValidDer_withTextData()
    {
        $textData = 'This is plain text, not binary DER data';
        $this->assertFalse($this->pemDerFormat->isValidDer($textData));
    }
    
    public function test_isValidDer_withShortData()
    {
        $shortData = 'x';
        $this->assertFalse($this->pemDerFormat->isValidDer($shortData));
    }
    
    public function test_isValidDer_withEmptyData()
    {
        $this->assertFalse($this->pemDerFormat->isValidDer(''));
    }
    
    public function test_pemToDer_derToPem_roundTrip()
    {
        // 使用二进制数据进行往返测试
        $originalData = "\x30\x82\x01\x00\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $type = 'TEST DATA';
        
        // DER -> PEM -> DER
        $pemData = $this->pemDerFormat->derToPem($originalData, $type);
        $recoveredData = $this->pemDerFormat->pemToDer($pemData);
        
        $this->assertSame($originalData, $recoveredData);
    }
} 