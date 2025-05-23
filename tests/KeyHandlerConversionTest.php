<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * KeyHandler密钥转换功能测试
 */
class KeyHandlerConversionTest extends TestCase
{
    private KeyHandler $keyHandler;
    
    protected function setUp(): void
    {
        $this->keyHandler = new KeyHandler();
    }
    
    public function test_privateKeyToPublicKey_withValidRsaPrivateKey()
    {
        // 先生成一个RSA密钥对
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $expectedPublicKey = $keyPair['public_key'];
        
        // 从私钥提取公钥
        $extractedPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        
        // 验证提取的公钥格式正确
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $extractedPublicKey);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $extractedPublicKey);
        
        // 验证提取的公钥与生成的公钥一致
        $this->assertSame($expectedPublicKey, $extractedPublicKey);
        
        // 验证提取的公钥可以被OpenSSL加载
        $publicKeyResource = openssl_pkey_get_public($extractedPublicKey);
        $this->assertNotFalse($publicKeyResource);
    }
    
    public function test_privateKeyToPublicKey_withValidEcPrivateKey()
    {
        // 先生成一个EC密钥对
        $keyPair = $this->keyHandler->generateEcKeyPair();
        $privateKey = $keyPair['private_key'];
        $expectedPublicKey = $keyPair['public_key'];
        
        // 从私钥提取公钥
        $extractedPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        
        // 验证提取的公钥与生成的公钥一致
        $this->assertSame($expectedPublicKey, $extractedPublicKey);
        
        // 验证密钥类型
        $publicKeyResource = openssl_pkey_get_public($extractedPublicKey);
        $keyDetails = openssl_pkey_get_details($publicKeyResource);
        $this->assertSame(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
    }
    
    public function test_privateKeyToPublicKey_withInvalidPrivateKey()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');
        
        $invalidPrivateKey = "-----BEGIN PRIVATE KEY-----\nInvalidKeyData\n-----END PRIVATE KEY-----";
        $this->keyHandler->privateKeyToPublicKey($invalidPrivateKey);
    }
    
    public function test_privateKeyToPublicKey_withEmptyString()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');
        
        $this->keyHandler->privateKeyToPublicKey('');
    }
    
    public function test_privateKeyToPublicKey_withNonPemFormat()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');
        
        $this->keyHandler->privateKeyToPublicKey('This is not a PEM format key');
    }
    
    public function test_privateKeyToPublicKey_withPublicKeyInput()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');
        
        // 生成密钥对，然后尝试用公钥作为输入
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $publicKey = $keyPair['public_key'];
        
        $this->keyHandler->privateKeyToPublicKey($publicKey);
    }
    
    public function test_privateKeyToPublicKey_withMalformedPemHeaders()
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');
        
        $malformedKey = "-----BEGIN INVALID KEY-----\nSGVsbG8=\n-----END INVALID KEY-----";
        $this->keyHandler->privateKeyToPublicKey($malformedKey);
    }
    
    public function test_privateKeyToPublicKey_consistency_multipleKeys()
    {
        // 生成多个密钥对，验证转换的一致性
        for ($i = 0; $i < 3; $i++) {
            $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
            $privateKey = $keyPair['private_key'];
            $expectedPublicKey = $keyPair['public_key'];
            
            $extractedPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
            $this->assertSame($expectedPublicKey, $extractedPublicKey);
        }
    }
    
    public function test_privateKeyToPublicKey_withDifferentKeySizes()
    {
        $keySizes = [1024, 2048];
        
        foreach ($keySizes as $keySize) {
            $keyPair = $this->keyHandler->generateRsaKeyPair($keySize);
            $privateKey = $keyPair['private_key'];
            $expectedPublicKey = $keyPair['public_key'];
            
            $extractedPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
            $this->assertSame($expectedPublicKey, $extractedPublicKey);
            
            // 验证密钥大小
            $publicKeyResource = openssl_pkey_get_public($extractedPublicKey);
            $keyDetails = openssl_pkey_get_details($publicKeyResource);
            $this->assertSame($keySize, $keyDetails['bits']);
        }
    }
    
    public function test_privateKeyToPublicKey_withDifferentEcCurves()
    {
        $curves = ['prime256v1', 'secp384r1', 'secp521r1'];
        
        foreach ($curves as $curve) {
            $keyPair = $this->keyHandler->generateEcKeyPair($curve);
            $privateKey = $keyPair['private_key'];
            $expectedPublicKey = $keyPair['public_key'];
            
            $extractedPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
            $this->assertSame($expectedPublicKey, $extractedPublicKey);
            
            // 验证曲线类型
            $publicKeyResource = openssl_pkey_get_public($extractedPublicKey);
            $keyDetails = openssl_pkey_get_details($publicKeyResource);
            $this->assertSame($curve, $keyDetails['ec']['curve_name']);
        }
    }
} 