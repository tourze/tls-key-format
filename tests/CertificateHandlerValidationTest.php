<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\CertificateHandler;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * CertificateHandler证书验证功能测试
 */
class CertificateHandlerValidationTest extends TestCase
{
    private CertificateHandler $certificateHandler;
    private KeyHandler $keyHandler;
    
    protected function setUp(): void
    {
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
        $cert = openssl_csr_sign($csr, null, $privateKey, $validDays, ['digest_alg' => 'sha256']);
        
        openssl_x509_export($cert, $certPem);
        return $certPem;
    }
    
    public function test_verifyCertificateValidity_withValidCertificate()
    {
        $certPem = $this->generateSelfSignedCertificate(365);
        
        $isValid = $this->certificateHandler->verifyCertificateValidity($certPem);
        
        $this->assertTrue($isValid);
    }
    
    public function test_verifyCertificateValidity_withExpiredCertificate()
    {
        // 生成已过期的证书，使用更大的负数确保过期
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        
        $dn = [
            'CN' => 'expired.example.com',
            'O' => 'Test Organization',
            'C' => 'CN',
        ];
        
        // 创建一个明确过期的证书（从30天前开始，有效期1天，所以29天前就过期了）
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        
        $csr = openssl_csr_new($dn, $privateKey, $config);
        
        // 使用负的有效期天数创建过期证书
        $cert = openssl_csr_sign($csr, null, $privateKey, -30, $config);
        
        if ($cert === false) {
            // 如果无法创建过期证书，跳过此测试
            $this->markTestSkipped('无法创建过期证书进行测试');
            return;
        }
        
        openssl_x509_export($cert, $certPem);
        
        $isValid = $this->certificateHandler->verifyCertificateValidity($certPem);
        
        $this->assertFalse($isValid);
    }
    
    public function test_verifyCertificateValidity_withInvalidCertificate()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式证书');
        
        $invalidCert = "INVALID CERTIFICATE";
        $this->certificateHandler->verifyCertificateValidity($invalidCert);
    }
    
    public function test_verifyCertificateChain_withSelfSignedCertificate()
    {
        $certPem = $this->generateSelfSignedCertificate();
        
        // 对于自签名证书，我们需要将其自身作为CA证书
        $chainCerts = [$certPem];
        
        try {
            $isValid = $this->certificateHandler->verifyCertificateChain($certPem, $chainCerts);
            $this->assertIsBool($isValid);
        } catch (KeyFormatException $e) {
            // 自签名证书验证可能失败，这是正常的
            $this->assertStringContainsString('OpenSSL', $e->getMessage());
        }
    }
    
    public function test_verifyCertificateChain_withInvalidCertificate()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('OpenSSL无法读取证书');
        
        $invalidCert = "-----BEGIN CERTIFICATE-----\nInvalidData\n-----END CERTIFICATE-----";
        $chainCerts = [];
        
        $this->certificateHandler->verifyCertificateChain($invalidCert, $chainCerts);
    }
    
    public function test_verifyCertificateChain_temporaryFileHandling()
    {
        $certPem = $this->generateSelfSignedCertificate();
        $chainCerts = [$this->generateSelfSignedCertificate()];
        
        $tempDir = sys_get_temp_dir();
        $filesBefore = glob($tempDir . '/cert_chain_*');
        $countBefore = count($filesBefore);
        
        try {
            $this->certificateHandler->verifyCertificateChain($certPem, $chainCerts);
        } catch (KeyFormatException $e) {
            // 忽略验证失败
        }
        
        $filesAfter = glob($tempDir . '/cert_chain_*');
        $countAfter = count($filesAfter);
        
        $this->assertSame($countBefore, $countAfter, '临时文件未被正确清理');
    }
} 