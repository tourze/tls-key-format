<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * KeyHandler密钥转换功能测试
 *
 * @internal
 */
#[CoversClass(KeyHandler::class)]
final class KeyHandlerConversionTest extends TestCase
{
    private KeyHandler $keyHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyHandler = new KeyHandler();
    }

    public function testPrivateKeyToPublicKeyWithValidRsaPrivateKey(): void
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

    public function testPrivateKeyToPublicKeyWithValidEcPrivateKey(): void
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
        $this->assertNotFalse($publicKeyResource);
        $keyDetails = openssl_pkey_get_details($publicKeyResource);
        if (false === $keyDetails) {
            self::fail('Failed to get key details');
        }
        $this->assertSame(OPENSSL_KEYTYPE_EC, $keyDetails['type']);
    }

    public function testPrivateKeyToPublicKeyWithInvalidPrivateKey(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');

        $invalidPrivateKey = "-----BEGIN PRIVATE KEY-----\nInvalidKeyData\n-----END PRIVATE KEY-----";
        $this->keyHandler->privateKeyToPublicKey($invalidPrivateKey);
    }

    public function testPrivateKeyToPublicKeyWithEmptyString(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');

        $this->keyHandler->privateKeyToPublicKey('');
    }

    public function testPrivateKeyToPublicKeyWithNonPemFormat(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');

        $this->keyHandler->privateKeyToPublicKey('This is not a PEM format key');
    }

    public function testPrivateKeyToPublicKeyWithPublicKeyInput(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');

        // 生成密钥对，然后尝试用公钥作为输入
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $publicKey = $keyPair['public_key'];

        $this->keyHandler->privateKeyToPublicKey($publicKey);
    }

    public function testPrivateKeyToPublicKeyWithMalformedPemHeaders(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');

        $malformedKey = "-----BEGIN INVALID KEY-----\nSGVsbG8=\n-----END INVALID KEY-----";
        $this->keyHandler->privateKeyToPublicKey($malformedKey);
    }

    public function testPrivateKeyToPublicKeyConsistencyMultipleKeys(): void
    {
        // 生成多个密钥对，验证转换的一致性
        for ($i = 0; $i < 3; ++$i) {
            $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
            $privateKey = $keyPair['private_key'];
            $expectedPublicKey = $keyPair['public_key'];

            $extractedPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
            $this->assertSame($expectedPublicKey, $extractedPublicKey);
        }
    }

    public function testPrivateKeyToPublicKeyWithDifferentKeySizes(): void
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
            $this->assertNotFalse($publicKeyResource);
            $keyDetails = openssl_pkey_get_details($publicKeyResource);
            if (false === $keyDetails) {
                self::fail('Failed to get key details');
            }
            $this->assertSame($keySize, $keyDetails['bits']);
        }
    }

    public function testPrivateKeyToPublicKeyWithDifferentEcCurves(): void
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
            $this->assertNotFalse($publicKeyResource);
            $keyDetails = openssl_pkey_get_details($publicKeyResource);
            if (false === $keyDetails) {
                self::fail('Failed to get key details');
            }
            $this->assertSame($curve, $keyDetails['ec']['curve_name']);
        }
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

    public function testGenerateEcKeyPair(): void
    {
        $result = $this->keyHandler->generateEcKeyPair();
        $this->assertArrayHasKey('private_key', $result);
        $this->assertArrayHasKey('public_key', $result);
    }

    public function testGenerateRsaKeyPair(): void
    {
        $result = $this->keyHandler->generateRsaKeyPair();
        $this->assertArrayHasKey('private_key', $result);
        $this->assertArrayHasKey('public_key', $result);
    }
}
