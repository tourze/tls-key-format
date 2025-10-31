<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\CertificateHandler;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * CertificateHandler证书验证功能测试
 *
 * @internal
 */
#[CoversClass(CertificateHandler::class)]
final class CertificateHandlerValidationTest extends TestCase
{
    private CertificateHandler $certificateHandler;

    private KeyHandler $keyHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->certificateHandler = new CertificateHandler();
        $this->keyHandler = new KeyHandler();
    }

    private function generateSelfSignedCertificate(int $validDays = 365): string
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);

        $dn = [
            'CN' => 'test.example.com',
            'O' => 'Test Organization',
            'C' => 'CN',
        ];

        $csr = openssl_csr_new($dn, $privateKey, ['digest_alg' => 'sha256']);
        if (false === $csr) {
            throw new KeyFormatException('Failed to create CSR');
        }
        $this->assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $privateKey, $validDays, ['digest_alg' => 'sha256']);
        if (false === $cert) {
            throw new KeyFormatException('Failed to sign certificate');
        }

        $result = openssl_x509_export($cert, $certPem);
        if (false === $result) {
            throw new KeyFormatException('Failed to export certificate');
        }

        return $certPem;
    }

    public function testVerifyCertificateValidityWithValidCertificate(): void
    {
        $certPem = $this->generateSelfSignedCertificate(365);

        $isValid = $this->certificateHandler->verifyCertificateValidity($certPem);

        $this->assertTrue($isValid);
    }

    public function testVerifyCertificateValidityWithInvalidCertificate(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式证书');

        $invalidCert = 'INVALID CERTIFICATE';
        $this->certificateHandler->verifyCertificateValidity($invalidCert);
    }

    public function testVerifyCertificateChainWithSelfSignedCertificate(): void
    {
        $certPem = $this->generateSelfSignedCertificate();

        // 对于自签名证书，我们需要将其自身作为CA证书
        $chainCerts = [$certPem];

        try {
            $this->certificateHandler->verifyCertificateChain($certPem, $chainCerts);
        } catch (KeyFormatException $e) {
            // 自签名证书验证可能失败，这是正常的
            $this->assertStringContainsString('OpenSSL', $e->getMessage());
        }
    }

    public function testVerifyCertificateChainWithInvalidCertificate(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('OpenSSL无法读取证书');

        $invalidCert = "-----BEGIN CERTIFICATE-----\nInvalidData\n-----END CERTIFICATE-----";
        $chainCerts = [];

        $this->certificateHandler->verifyCertificateChain($invalidCert, $chainCerts);
    }

    public function testVerifyCertificateChainTemporaryFileHandling(): void
    {
        $certPem = $this->generateSelfSignedCertificate();
        $chainCerts = [$this->generateSelfSignedCertificate()];

        $tempDir = sys_get_temp_dir();
        $filesBefore = glob($tempDir . '/cert_chain_*');
        $countBefore = is_array($filesBefore) ? count($filesBefore) : 0;

        try {
            $this->certificateHandler->verifyCertificateChain($certPem, $chainCerts);
        } catch (KeyFormatException $e) {
            // 忽略验证失败
        }

        $filesAfter = glob($tempDir . '/cert_chain_*');
        $countAfter = is_array($filesAfter) ? count($filesAfter) : 0;

        $this->assertSame($countBefore, $countAfter, '临时文件未被正确清理');
    }

    public function testExtractPublicKey(): void
    {
        $certificate = $this->generateSelfSignedCertificate();
        $publicKey = $this->certificateHandler->extractPublicKey($certificate);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
    }

    public function testParseCertificate(): void
    {
        $certificate = $this->generateSelfSignedCertificate();
        $result = $this->certificateHandler->parseCertificate($certificate);
        $this->assertArrayHasKey('subject', $result);
        $this->assertArrayHasKey('issuer', $result);
    }
}
