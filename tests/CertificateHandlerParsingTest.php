<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\CertificateHandler;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * CertificateHandler证书解析功能测试
 */
class CertificateHandlerParsingTest extends TestCase
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
        // 生成私钥
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        
        // 创建证书签名请求
        $dn = [
            'C' => 'CN',
            'ST' => 'Beijing',
            'L' => 'Beijing',
            'O' => 'Test Organization',
            'OU' => 'Test Unit',
            'CN' => 'test.example.com',
        ];
        
        $csr = openssl_csr_new($dn, $privateKey, ['digest_alg' => 'sha256']);
        
        // 创建自签名证书
        $cert = openssl_csr_sign($csr, null, $privateKey, $validDays, ['digest_alg' => 'sha256']);
        
        // 导出证书
        openssl_x509_export($cert, $certPem);
        
        return $certPem;
    }
    
    
    public function test_parseCertificate_withValidCertificate()
    {
        $certPem = $this->generateSelfSignedCertificate();
        
        $certInfo = $this->certificateHandler->parseCertificate($certPem);
        
        // 验证包含基本字段
        $this->assertArrayHasKey('subject', $certInfo);
        $this->assertArrayHasKey('issuer', $certInfo);
        $this->assertArrayHasKey('validFrom', $certInfo);
        $this->assertArrayHasKey('validTo', $certInfo);
        $this->assertArrayHasKey('validFrom_time_t', $certInfo);
        $this->assertArrayHasKey('validTo_time_t', $certInfo);
        
        // 验证主题信息
        $this->assertArrayHasKey('CN', $certInfo['subject']);
        $this->assertSame('test.example.com', $certInfo['subject']['CN']);
        
        // 验证有效期时间戳是数字
        $this->assertIsInt($certInfo['validFrom_time_t']);
        $this->assertIsInt($certInfo['validTo_time_t']);
        
        // 验证有效期合理性（validTo > validFrom）
        $this->assertGreaterThan($certInfo['validFrom_time_t'], $certInfo['validTo_time_t']);
    }
    
    public function test_parseCertificate_withInvalidPemFormat()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式证书');
        
        $invalidPem = "INVALID CERTIFICATE DATA";
        $this->certificateHandler->parseCertificate($invalidPem);
    }
    
    public function test_parseCertificate_withInvalidCertificateContent()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('OpenSSL无法解析证书');
        
        $invalidCertPem = "-----BEGIN CERTIFICATE-----\nSGVsbG8gV29ybGQ=\n-----END CERTIFICATE-----";
        $this->certificateHandler->parseCertificate($invalidCertPem);
    }
    
    public function test_parseCertificate_withEmptyString()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无效的PEM格式证书');
        
        $this->certificateHandler->parseCertificate('');
    }
    
    public function test_parseCertificate_withPrivateKeyInstead()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('OpenSSL无法解析证书');
        
        // 传入私钥而不是证书
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        
        $this->certificateHandler->parseCertificate($privateKey);
    }
    
    public function test_extractPublicKey_withValidCertificate()
    {
        $certPem = $this->generateSelfSignedCertificate();
        
        $publicKey = $this->certificateHandler->extractPublicKey($certPem);
        
        // 验证返回的是PEM格式公钥
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $publicKey);
        
        // 验证公钥可以被OpenSSL加载
        $publicKeyResource = openssl_pkey_get_public($publicKey);
        $this->assertNotFalse($publicKeyResource);
        
        // 验证公钥类型
        $keyDetails = openssl_pkey_get_details($publicKeyResource);
        $this->assertSame(OPENSSL_KEYTYPE_RSA, $keyDetails['type']);
    }
    
    public function test_extractPublicKey_withInvalidCertificate()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('OpenSSL无法读取证书');
        
        $invalidCertPem = "-----BEGIN CERTIFICATE-----\nInvalidData\n-----END CERTIFICATE-----";
        $this->certificateHandler->extractPublicKey($invalidCertPem);
    }
    
    public function test_extractPublicKey_withEmptyString()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('OpenSSL无法读取证书');
        
        $this->certificateHandler->extractPublicKey('');
    }
    
    public function test_extractPublicKey_consistencyWithGeneratedKey()
    {
        // 生成密钥对
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        $expectedPublicKey = $keyPair['public_key'];
        
        // 创建使用该密钥的证书
        $dn = ['CN' => 'test.example.com'];
        $csr = openssl_csr_new($dn, $privateKey);
        $cert = openssl_csr_sign($csr, null, $privateKey, 365);
        openssl_x509_export($cert, $certPem);
        
        // 从证书提取公钥
        $extractedPublicKey = $this->certificateHandler->extractPublicKey($certPem);
        
        // 验证提取的公钥与原始公钥一致
        $this->assertSame($expectedPublicKey, $extractedPublicKey);
    }
    
    public function test_parseCertificate_withDifferentSubjects()
    {
        // 测试不同的主题信息
        $subjects = [
            ['CN' => 'example.com'],
            ['CN' => 'test.com', 'O' => 'Test Org'],
            ['CN' => 'multi.example.com', 'O' => 'Multi Org', 'C' => 'US'],
        ];
        
        foreach ($subjects as $subject) {
            $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
            $privateKey = openssl_pkey_get_private($keyPair['private_key']);
            
            $csr = openssl_csr_new($subject, $privateKey);
            $cert = openssl_csr_sign($csr, null, $privateKey, 365);
            openssl_x509_export($cert, $certPem);
            
            $certInfo = $this->certificateHandler->parseCertificate($certPem);
            
            // 验证主题信息正确
            foreach ($subject as $key => $value) {
                $this->assertArrayHasKey($key, $certInfo['subject']);
                $this->assertSame($value, $certInfo['subject'][$key]);
            }
        }
    }
    
    public function test_parseCertificate_withEcCertificate()
    {
        // 使用EC密钥生成证书
        $keyPair = $this->keyHandler->generateEcKeyPair();
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        
        $dn = ['CN' => 'ec-test.example.com'];
        $csr = openssl_csr_new($dn, $privateKey);
        $cert = openssl_csr_sign($csr, null, $privateKey, 365);
        openssl_x509_export($cert, $certPem);
        
        $certInfo = $this->certificateHandler->parseCertificate($certPem);
        
        $this->assertSame('ec-test.example.com', $certInfo['subject']['CN']);
        
        // 验证可以提取EC公钥
        $publicKey = $this->certificateHandler->extractPublicKey($certPem);
        $publicKeyResource = openssl_pkey_get_public($publicKey);
        $keyDetails = openssl_pkey_get_details($publicKeyResource);
        $this->assertSame(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
    }

    public function test_parseCertificate_withMinimalValidCertificate()
    {
        // 测试最小有效证书
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        
        // 只包含必需的CN字段
        $dn = ['CN' => 'minimal.test'];
        $csr = openssl_csr_new($dn, $privateKey);
        $cert = openssl_csr_sign($csr, null, $privateKey, 1); // 最短有效期1天
        openssl_x509_export($cert, $certPem);
        
        $certInfo = $this->certificateHandler->parseCertificate($certPem);
        
        $this->assertSame('minimal.test', $certInfo['subject']['CN']);
        $this->assertArrayHasKey('subject', $certInfo);
        $this->assertArrayHasKey('issuer', $certInfo);
    }

    public function test_extractPublicKey_withDifferentKeyTypes()
    {
        // 测试不同密钥类型的公钥提取
        $keyTypes = [
            ['rsa', 1024],
            ['rsa', 2048],
            ['ec', 'prime256v1'],
            ['ec', 'secp384r1'],
        ];
        
        foreach ($keyTypes as [$type, $param]) {
            if ($type === 'rsa') {
                $keyPair = $this->keyHandler->generateRsaKeyPair($param);
                $expectedType = OPENSSL_KEYTYPE_RSA;
            } else {
                $keyPair = $this->keyHandler->generateEcKeyPair($param);
                $expectedType = OPENSSL_KEYTYPE_EC;
            }
            
            $privateKey = openssl_pkey_get_private($keyPair['private_key']);
            $dn = ['CN' => "test-{$type}-{$param}.example.com"];
            $csr = openssl_csr_new($dn, $privateKey);
            $cert = openssl_csr_sign($csr, null, $privateKey, 365);
            openssl_x509_export($cert, $certPem);
            
            $publicKey = $this->certificateHandler->extractPublicKey($certPem);
            $publicKeyResource = openssl_pkey_get_public($publicKey);
            $keyDetails = openssl_pkey_get_details($publicKeyResource);
            
            $this->assertSame($expectedType, $keyDetails['type']);
        }
    }

    public function test_parseCertificate_withSpecialCharactersInSubject()
    {
        // 测试主题中包含特殊字符的证书
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        
        $dn = [
            'CN' => 'test-special.example.com',
            'O' => 'Test & Company, Ltd.',
            'OU' => 'R&D Department',
            'L' => 'San José',
            'C' => 'US',
        ];
        
        $csr = openssl_csr_new($dn, $privateKey);
        $cert = openssl_csr_sign($csr, null, $privateKey, 365);
        openssl_x509_export($cert, $certPem);
        
        $certInfo = $this->certificateHandler->parseCertificate($certPem);
        
        $this->assertSame('test-special.example.com', $certInfo['subject']['CN']);
        $this->assertSame('Test & Company, Ltd.', $certInfo['subject']['O']);
        $this->assertSame('R&D Department', $certInfo['subject']['OU']);
        $this->assertSame('San José', $certInfo['subject']['L']);
    }

    public function test_extractPublicKey_memoryManagement()
    {
        // 测试多次提取公钥时的内存管理
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = openssl_pkey_get_private($keyPair['private_key']);
        $dn = ['CN' => 'memory-test.example.com'];
        $csr = openssl_csr_new($dn, $privateKey);
        $cert = openssl_csr_sign($csr, null, $privateKey, 365);
        openssl_x509_export($cert, $certPem);
        
        $initialMemory = memory_get_usage();
        
        // 多次提取公钥
        for ($i = 0; $i < 10; $i++) {
            $publicKey = $this->certificateHandler->extractPublicKey($certPem);
            $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
        }
        
        $finalMemory = memory_get_usage();
        $memoryIncrease = $finalMemory - $initialMemory;
        
        // 内存增长应该是合理的（小于1MB）
        $this->assertLessThan(1024 * 1024, $memoryIncrease);
    }
} 