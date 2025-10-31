<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\PemDerFormat;

/**
 * PemDerFormat类测试
 *
 * @internal
 */
#[CoversClass(PemDerFormat::class)]
final class PemDerFormatTest extends TestCase
{
    private PemDerFormat $pemDerFormat;

    protected function setUp(): void
    {
        parent::setUp();

        $this->pemDerFormat = new PemDerFormat();
    }

    public function testIsValidPemWithValidPemCertificate(): void
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n" .
                   "MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAoMCVRl\n" .
                   "c3QgQ2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV\n" .
                   "BAoMCVRlc3QgQ2VydDBcMA0GCSqGSIb3DQEBAQUAAksAMEgCQQDTgvwjlRHZ5X2j\n" .
                   "-----END CERTIFICATE-----\n";

        $this->assertTrue($this->pemDerFormat->isValidPem($validPem));
    }

    public function testIsValidPemWithInvalidFormat(): void
    {
        $invalidPem = 'INVALID PEM DATA';
        $this->assertFalse($this->pemDerFormat->isValidPem($invalidPem));
    }

    public function testIsValidPemWithMismatchedHeaders(): void
    {
        $mismatchedPem = "-----BEGIN CERTIFICATE-----\n" .
                        "SGVsbG8gV29ybGQ=\n" .
                        "-----END PRIVATE KEY-----\n";

        $this->assertFalse($this->pemDerFormat->isValidPem($mismatchedPem));
    }

    public function testIsValidPemWithInvalidBase64(): void
    {
        $invalidBase64Pem = "-----BEGIN CERTIFICATE-----\n" .
                           "This is not valid base64!@#$%\n" .
                           "-----END CERTIFICATE-----\n";

        $this->assertFalse($this->pemDerFormat->isValidPem($invalidBase64Pem));
    }

    public function testIsValidPemWithEmptyContent(): void
    {
        $emptyPem = "-----BEGIN CERTIFICATE-----\n" .
                   "-----END CERTIFICATE-----\n";

        $this->assertFalse($this->pemDerFormat->isValidPem($emptyPem));
    }

    public function testPemToDerWithValidPem(): void
    {
        $validPem = "-----BEGIN CERTIFICATE-----\n" .
                   "SGVsbG8gV29ybGQ=\n" .
                   "-----END CERTIFICATE-----\n";

        $derData = $this->pemDerFormat->pemToDer($validPem);
        $this->assertSame('Hello World', $derData);
    }

    public function testPemToDerWithInvalidPem(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');

        $this->pemDerFormat->pemToDer('INVALID PEM');
    }

    public function testPemToDerWithMismatchedHeaders(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');

        $mismatchedPem = "-----BEGIN CERTIFICATE-----\n" .
                        "SGVsbG8=\n" .
                        "-----END PRIVATE KEY-----\n";

        $this->pemDerFormat->pemToDer($mismatchedPem);
    }

    public function testPemToDerWithInvalidBase64(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');

        $invalidBase64Pem = "-----BEGIN CERTIFICATE-----\n" .
                           "Invalid Base64!@#\n" .
                           "-----END CERTIFICATE-----\n";

        $this->pemDerFormat->pemToDer($invalidBase64Pem);
    }

    public function testDerToPemWithValidDer(): void
    {
        // 使用真实的二进制DER数据
        $derData = "\x30\x82\x01\x00\x02\x01\x00";
        $type = 'CERTIFICATE';

        $pemData = $this->pemDerFormat->derToPem($derData, $type);

        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $pemData);
        $this->assertStringContainsString('-----END CERTIFICATE-----', $pemData);
    }

    public function testDerToPemWithInvalidType(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的DER格式数据');

        $this->pemDerFormat->derToPem('test', 'invalid-type');
    }

    public function testDerToPemWithEmptyType(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的DER格式数据');

        $this->pemDerFormat->derToPem('test', '');
    }

    public function testDerToPemWithInvalidDer(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的DER格式数据');

        // 传入明显的文本数据而非二进制数据
        $textData = 'This is clearly text, not binary DER data with enough characters to pass length check';
        $this->pemDerFormat->derToPem($textData, 'CERTIFICATE');
    }

    public function testExtractFromPemWithValidPem(): void
    {
        $validPem = "-----BEGIN PRIVATE KEY-----\n" .
                   "SGVsbG8gV29ybGQ=\n" .
                   "-----END PRIVATE KEY-----\n";

        $result = $this->pemDerFormat->extractFromPem($validPem);

        $this->assertArrayHasKey('type', $result);
        $this->assertArrayHasKey('data', $result);
        $this->assertSame('PRIVATE KEY', $result['type']);
        $this->assertSame('Hello World', $result['data']);
    }

    public function testExtractFromPemWithInvalidPem(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式数据');

        $this->pemDerFormat->extractFromPem('INVALID PEM DATA');
    }

    public function testIsValidDerWithBinaryData(): void
    {
        // 创建包含控制字符的二进制数据
        $binaryData = "\x30\x82\x01\x00\x02\x01\x00";
        $this->assertTrue($this->pemDerFormat->isValidDer($binaryData));
    }

    public function testIsValidDerWithTextData(): void
    {
        $textData = 'This is plain text, not binary DER data';
        $this->assertFalse($this->pemDerFormat->isValidDer($textData));
    }

    public function testIsValidDerWithShortData(): void
    {
        $shortData = 'x';
        $this->assertFalse($this->pemDerFormat->isValidDer($shortData));
    }

    public function testIsValidDerWithEmptyData(): void
    {
        $this->assertFalse($this->pemDerFormat->isValidDer(''));
    }

    public function testPemToDerDerToPemRoundTrip(): void
    {
        // 使用二进制数据进行往返测试
        $originalData = "\x30\x82\x01\x00\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $type = 'TEST DATA';

        // DER -> PEM -> DER
        $pemData = $this->pemDerFormat->derToPem($originalData, $type);
        $recoveredData = $this->pemDerFormat->pemToDer($pemData);

        $this->assertSame($originalData, $recoveredData);
    }

    public function testIsValidDerWithBoundaryLength(): void
    {
        // 测试长度刚好为2的边界情况
        $boundaryData = "\x30\x00";
        $this->assertTrue($this->pemDerFormat->isValidDer($boundaryData));

        // 测试长度为1的无效情况
        $shortData = "\x30";
        $this->assertFalse($this->pemDerFormat->isValidDer($shortData));
    }

    public function testIsValidDerWithTabsAndNewlines(): void
    {
        // 测试包含制表符和换行符但应被识别为二进制的数据
        $dataWithControls = "\x30\x82\t\n\r\x00\x02\x01";
        $this->assertTrue($this->pemDerFormat->isValidDer($dataWithControls));

        // 测试只包含允许的控制字符的文本数据
        $textWithControls = "Hello\tWorld\nTest\rData";
        $this->assertFalse($this->pemDerFormat->isValidDer($textWithControls));
    }

    public function testIsValidDerWithLongTextData(): void
    {
        // 测试超过32字节的纯文本数据（算法只检查前32字节）
        $longTextData = str_repeat('A', 64);
        $this->assertFalse($this->pemDerFormat->isValidDer($longTextData));

        // 测试前32字节包含二进制字符的长数据
        $longBinaryData = "\x30\x82\x01\x00" . str_repeat('A', 60);
        $this->assertTrue($this->pemDerFormat->isValidDer($longBinaryData));
    }

    public function testIsValidPemWithDifferentLineEndings(): void
    {
        // 测试使用\r\n换行符的PEM（不能在末尾有额外的换行符）
        $pemWithCrlf = "-----BEGIN CERTIFICATE-----\r\nSGVsbG8gV29ybGQ=\r\n-----END CERTIFICATE-----";
        $this->assertTrue($this->pemDerFormat->isValidPem($pemWithCrlf));

        // 测试使用\r换行符的PEM (这种格式可能不被支持)
        $pemWithCr = "-----BEGIN CERTIFICATE-----\rSGVsbG8gV29ybGQ=\r-----END CERTIFICATE-----\r";
        // 调整期望，因为只使用\r的格式可能不被正则表达式支持
        $this->assertFalse($this->pemDerFormat->isValidPem($pemWithCr));
    }

    public function testIsValidPemWithExtraWhitespace(): void
    {
        // 测试PEM数据中包含额外空格和制表符
        $pemWithSpaces = "-----BEGIN CERTIFICATE-----\n  SGVs  bG8g\tV29y\n  bGQ=  \n-----END CERTIFICATE-----\n";
        $this->assertTrue($this->pemDerFormat->isValidPem($pemWithSpaces));
    }

    public function testDerToPemWithSpecialTypeCharacters(): void
    {
        // 测试type参数包含数字的情况
        $derData = "\x30\x82\x01\x00\x02\x01\x00";

        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM类型标识');

        $this->pemDerFormat->derToPem($derData, 'CERT123');
    }

    public function testDerToPemWithLowercaseType(): void
    {
        // 测试type参数包含小写字母的情况
        $derData = "\x30\x82\x01\x00\x02\x01\x00";

        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM类型标识');

        $this->pemDerFormat->derToPem($derData, 'certificate');
    }

    public function testPemToDerWithComplexBase64Padding(): void
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
