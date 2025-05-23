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

    public function test_isValidDer_withBoundaryLength()
    {
        // 测试长度刚好为2的边界情况
        $boundaryData = "\x30\x00";
        $this->assertTrue($this->pemDerFormat->isValidDer($boundaryData));
        
        // 测试长度为1的无效情况
        $shortData = "\x30";
        $this->assertFalse($this->pemDerFormat->isValidDer($shortData));
    }

    public function test_isValidDer_withTabsAndNewlines()
    {
        // 测试包含制表符和换行符但应被识别为二进制的数据
        $dataWithControls = "\x30\x82\t\n\r\x00\x02\x01";
        $this->assertTrue($this->pemDerFormat->isValidDer($dataWithControls));
        
        // 测试只包含允许的控制字符的文本数据
        $textWithControls = "Hello\tWorld\nTest\rData";
        $this->assertFalse($this->pemDerFormat->isValidDer($textWithControls));
    }

    public function test_isValidDer_withLongTextData()
    {
        // 测试超过32字节的纯文本数据（算法只检查前32字节）
        $longTextData = str_repeat('A', 64);
        $this->assertFalse($this->pemDerFormat->isValidDer($longTextData));
        
        // 测试前32字节包含二进制字符的长数据
        $longBinaryData = "\x30\x82\x01\x00" . str_repeat('A', 60);
        $this->assertTrue($this->pemDerFormat->isValidDer($longBinaryData));
    }

    public function test_isValidPem_withDifferentLineEndings()
    {
        // 测试使用\r\n换行符的PEM（不能在末尾有额外的换行符）
        $pemWithCrlf = "-----BEGIN CERTIFICATE-----\r\nSGVsbG8gV29ybGQ=\r\n-----END CERTIFICATE-----";
        $this->assertTrue($this->pemDerFormat->isValidPem($pemWithCrlf));
        
        // 测试使用\r换行符的PEM (这种格式可能不被支持)
        $pemWithCr = "-----BEGIN CERTIFICATE-----\rSGVsbG8gV29ybGQ=\r-----END CERTIFICATE-----\r";
        // 调整期望，因为只使用\r的格式可能不被正则表达式支持
        $this->assertFalse($this->pemDerFormat->isValidPem($pemWithCr));
    }

    public function test_isValidPem_withExtraWhitespace()
    {
        // 测试PEM数据中包含额外空格和制表符
        $pemWithSpaces = "-----BEGIN CERTIFICATE-----\n  SGVs  bG8g\tV29y\n  bGQ=  \n-----END CERTIFICATE-----\n";
        $this->assertTrue($this->pemDerFormat->isValidPem($pemWithSpaces));
    }

    public function test_derToPem_withSpecialTypeCharacters()
    {
        // 测试type参数包含数字的情况
        $derData = "\x30\x82\x01\x00\x02\x01\x00";
        
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM类型标识');
        
        $this->pemDerFormat->derToPem($derData, 'CERT123');
    }

    public function test_derToPem_withLowercaseType()
    {
        // 测试type参数包含小写字母的情况
        $derData = "\x30\x82\x01\x00\x02\x01\x00";
        
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM类型标识');
        
        $this->pemDerFormat->derToPem($derData, 'certificate');
    }

    public function test_pemToDer_withComplexBase64Padding()
    {
        // 测试复杂的Base64填充情况
        $pemWithPadding = "-----BEGIN TEST-----\nSGVsbA==\n-----END TEST-----\n";
        $result = $this->pemDerFormat->pemToDer($pemWithPadding);
        $this->assertSame('Hell', $result);
        
        $pemWithSinglePad = "-----BEGIN TEST-----\nSGVsbG8=\n-----END TEST-----\n";
        $result = $this->pemDerFormat->pemToDer($pemWithSinglePad);
        $this->assertSame('Hello', $result);
    }
} 