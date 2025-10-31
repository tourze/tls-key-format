<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * 主测试类，集成所有CertificateHandler相关测试
 *
 * @internal
 */
#[CoversClass(CertificateHandler::class)]
final class CertificateHandlerTest extends TestCase
{
    /**
     * 测试CertificateHandler可以被实例化
     */
    public function testCertificateHandlerCanBeInstantiated(): void
    {
        $handler = new CertificateHandler();
        $this->assertInstanceOf(CertificateHandler::class, $handler);
    }

    public function testParseCertificate(): void
    {
        $handler = new CertificateHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->parseCertificate('invalid');
    }

    public function testExtractPublicKey(): void
    {
        $handler = new CertificateHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->extractPublicKey('invalid');
    }

    public function testVerifyCertificateValidity(): void
    {
        $handler = new CertificateHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->verifyCertificateValidity('invalid');
    }

    public function testVerifyCertificateChain(): void
    {
        $handler = new CertificateHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->verifyCertificateChain('invalid', []);
    }
}
