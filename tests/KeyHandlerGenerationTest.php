<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * KeyHandler密钥生成功能测试
 *
 * @internal
 */
#[CoversClass(KeyHandler::class)]
final class KeyHandlerGenerationTest extends TestCase
{
    private KeyHandler $keyHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyHandler = new KeyHandler();
    }

    public function testGenerateRsaKeyPairWithDefaultBits(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair();

        $this->assertArrayHasKey('private_key', $keyPair);
        $this->assertArrayHasKey('public_key', $keyPair);

        // 验证私钥格式
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['private_key']);
        $this->assertStringContainsString('-----END PRIVATE KEY-----', $keyPair['private_key']);

        // 验证公钥格式
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['public_key']);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $keyPair['public_key']);

        // 验证密钥可以被OpenSSL加载
        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);

        $publicKeyResource = openssl_pkey_get_public($keyPair['public_key']);
        $this->assertNotFalse($publicKeyResource);
    }

    public function testGenerateRsaKeyPairWith1024Bits(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);

        $this->assertArrayHasKey('private_key', $keyPair);
        $this->assertArrayHasKey('public_key', $keyPair);

        // 验证密钥长度（通过OpenSSL获取详情）
        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $keyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $keyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame(1024, $keyDetails['bits']);
        $this->assertSame(OPENSSL_KEYTYPE_RSA, $keyDetails['type']);
    }

    public function testGenerateRsaKeyPairWith4096Bits(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(4096);

        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $keyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $keyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame(4096, $keyDetails['bits']);
    }

    public function testGenerateEcKeyPairWithDefaultCurve(): void
    {
        $keyPair = $this->keyHandler->generateEcKeyPair();

        $this->assertArrayHasKey('private_key', $keyPair);
        $this->assertArrayHasKey('public_key', $keyPair);

        // 验证私钥格式
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['private_key']);
        $this->assertStringContainsString('-----END PRIVATE KEY-----', $keyPair['private_key']);

        // 验证公钥格式
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['public_key']);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $keyPair['public_key']);

        // 验证密钥类型
        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $keyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $keyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
        $this->assertSame('prime256v1', $keyDetails['ec']['curve_name']);
    }

    public function testGenerateEcKeyPairWithSecp384r1Curve(): void
    {
        $keyPair = $this->keyHandler->generateEcKeyPair('secp384r1');

        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $keyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $keyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
        $this->assertSame('secp384r1', $keyDetails['ec']['curve_name']);
    }

    public function testGenerateEcKeyPairWithSecp521r1Curve(): void
    {
        $keyPair = $this->keyHandler->generateEcKeyPair('secp521r1');

        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $keyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $keyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame('secp521r1', $keyDetails['ec']['curve_name']);
    }

    public function testGenerateEcKeyPairWithInvalidCurve(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('生成EC密钥对失败');

        $this->keyHandler->generateEcKeyPair('invalid-curve-name');
    }

    public function testGenerateRsaKeyPairWithInvalidBits(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('生成RSA密钥对失败');

        // 使用无效的位数（太小）
        $this->keyHandler->generateRsaKeyPair(128);
    }

    public function testGenerateRsaKeyPairMultipleCallsGenerateDifferentKeys(): void
    {
        $keyPair1 = $this->keyHandler->generateRsaKeyPair(1024);
        $keyPair2 = $this->keyHandler->generateRsaKeyPair(1024);

        // 两次生成的密钥应该不同
        $this->assertNotSame($keyPair1['private_key'], $keyPair2['private_key']);
        $this->assertNotSame($keyPair1['public_key'], $keyPair2['public_key']);
    }

    public function testGenerateEcKeyPairMultipleCallsGenerateDifferentKeys(): void
    {
        $keyPair1 = $this->keyHandler->generateEcKeyPair();
        $keyPair2 = $this->keyHandler->generateEcKeyPair();

        // 两次生成的密钥应该不同
        $this->assertNotSame($keyPair1['private_key'], $keyPair2['private_key']);
        $this->assertNotSame($keyPair1['public_key'], $keyPair2['public_key']);
    }

    public function testGenerateRsaKeyPairKeyPairConsistency(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);

        // 从私钥导出的公钥应该与生成的公钥一致
        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $derivedKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $derivedKeyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame($keyPair['public_key'], $derivedKeyDetails['key']);
    }

    public function testGenerateEcKeyPairKeyPairConsistency(): void
    {
        $keyPair = $this->keyHandler->generateEcKeyPair();

        // 从私钥导出的公钥应该与生成的公钥一致
        $privateKeyResource = openssl_pkey_get_private($keyPair['private_key']);
        $this->assertNotFalse($privateKeyResource);
        $derivedKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if (false === $derivedKeyDetails) {
            self::fail('Failed to get key details');
        }

        $this->assertSame($keyPair['public_key'], $derivedKeyDetails['key']);
    }

    public function testDecryptPrivateKey(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $encryptedKey = $this->keyHandler->encryptPrivateKey($keyPair['private_key'], 'password');
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, 'password');
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $decryptedKey);
    }

    public function testEncryptPrivateKey(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $encryptedKey = $this->keyHandler->encryptPrivateKey($keyPair['private_key'], 'password');
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $encryptedKey);
    }

    public function testPrivateKeyToPublicKey(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $publicKey = $this->keyHandler->privateKeyToPublicKey($keyPair['private_key']);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
    }
}
