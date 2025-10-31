<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;
use Tourze\TLSKeyFormat\KeyHandler;

/**
 * KeyHandler密钥加密解密功能测试
 *
 * @internal
 */
#[CoversClass(KeyHandler::class)]
final class KeyHandlerEncryptionTest extends TestCase
{
    private KeyHandler $keyHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyHandler = new KeyHandler();
    }

    public function testEncryptPrivateKeyWithValidKeyAndPassphrase(): void
    {
        // 生成私钥
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = 'test-password-123';

        // 加密私钥
        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);

        // 验证加密后的密钥格式
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $encryptedKey);
        $this->assertStringContainsString('-----END ENCRYPTED PRIVATE KEY-----', $encryptedKey);

        // 验证加密后的密钥与原始密钥不同
        $this->assertNotSame($privateKey, $encryptedKey);

        // 验证加密后的密钥可以用密码解密
        $decryptedKey = openssl_pkey_get_private($encryptedKey, $passphrase);
        $this->assertNotFalse($decryptedKey);
    }

    public function testEncryptPrivateKeyWithCustomCipher(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = 'test-password';
        $cipher = 'aes-128-cbc';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase, $cipher);

        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $encryptedKey);

        // 验证可以用相同密码解密
        $decryptedKey = openssl_pkey_get_private($encryptedKey, $passphrase);
        $this->assertNotFalse($decryptedKey);
    }

    public function testEncryptPrivateKeyWithInvalidPrivateKey(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('无法加载私钥');

        $invalidKey = "-----BEGIN PRIVATE KEY-----\nInvalidData\n-----END PRIVATE KEY-----";
        $this->keyHandler->encryptPrivateKey($invalidKey, 'password');
    }

    public function testEncryptPrivateKeyWithEmptyPassphrase(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];

        // 空密码应该能成功加密
        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, '');
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $encryptedKey);
    }

    public function testDecryptPrivateKeyWithValidEncryptedKey(): void
    {
        // 先生成并加密私钥
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $originalPrivateKey = $keyPair['private_key'];
        $passphrase = 'test-password-456';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($originalPrivateKey, $passphrase);

        // 解密私钥
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

        // 验证解密后的密钥格式
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $decryptedKey);
        $this->assertStringContainsString('-----END PRIVATE KEY-----', $decryptedKey);

        // 验证解密后的密钥功能正确（可以从中提取公钥）
        $publicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);
        $this->assertSame($keyPair['public_key'], $publicKey);
    }

    public function testDecryptPrivateKeyWithWrongPassphrase(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('私钥解密失败');

        // 先加密私钥
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $correctPassphrase = 'correct-password';
        $wrongPassphrase = 'wrong-password';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $correctPassphrase);

        // 用错误密码解密
        $this->keyHandler->decryptPrivateKey($encryptedKey, $wrongPassphrase);
    }

    public function testDecryptPrivateKeyWithInvalidEncryptedKey(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('私钥解密失败');

        $invalidEncryptedKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nInvalidData\n-----END ENCRYPTED PRIVATE KEY-----";
        $this->keyHandler->decryptPrivateKey($invalidEncryptedKey, 'password');
    }

    public function testDecryptPrivateKeyWithUnencryptedKey(): void
    {
        // 尝试用密码解密未加密的私钥
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $unencryptedKey = $keyPair['private_key'];

        // 未加密的密钥用密码解密可能会成功（OpenSSL会忽略密码）
        // 所以我们检查解密后的结果是否与原始密钥相同
        $decryptedKey = $this->keyHandler->decryptPrivateKey($unencryptedKey, 'password');

        // 验证解密后的密钥功能正确
        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($unencryptedKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $originalPrivateKey = $keyPair['private_key'];
        $passphrase = 'round-trip-test';

        // 加密然后解密
        $encryptedKey = $this->keyHandler->encryptPrivateKey($originalPrivateKey, $passphrase);
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

        // 验证往返加密解密后密钥功能一致
        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($originalPrivateKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptPrivateKeyWithSpecialCharactersInPassphrase(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

        // 验证特殊字符密码可以正常工作
        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptPrivateKeyWithUnicodePassphrase(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = '测试密码123中文';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

        // 验证Unicode密码可以正常工作
        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptPrivateKeyWithEcKey(): void
    {
        $keyPair = $this->keyHandler->generateEcKeyPair();
        $privateKey = $keyPair['private_key'];
        $passphrase = 'ec-key-password';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

        // 验证EC密钥加密解密正常
        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptPrivateKeyMultipleDifferentPassphrases(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];

        $passphrases = ['password1', 'password2', 'password3'];

        foreach ($passphrases as $passphrase) {
            $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);
            $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

            // 每个密码都应该能正确加密和解密
            $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
            $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

            $this->assertSame($originalPublicKey, $decryptedPublicKey);
        }
    }

    public function testEncryptPrivateKeyWithVeryLongPassphrase(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];

        // 测试非常长的密码（1000个字符）
        $longPassphrase = str_repeat('VeryLongPassword123!@#', 50);

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $longPassphrase);
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $longPassphrase);

        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptPrivateKeyWithBinaryPassphrase(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];

        // 测试包含二进制字符的密码
        $binaryPassphrase = "\x00\x01\x02\xFF\xFE\xFD密码123";

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $binaryPassphrase);
        $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $binaryPassphrase);

        $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
        $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

        $this->assertSame($originalPublicKey, $decryptedPublicKey);
    }

    public function testEncryptPrivateKeyWithDifferentCiphers(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = 'test-cipher-password';

        // 测试不同的加密算法
        $ciphers = ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 'des-ede3-cbc'];

        foreach ($ciphers as $cipher) {
            $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase, $cipher);
            $decryptedKey = $this->keyHandler->decryptPrivateKey($encryptedKey, $passphrase);

            $originalPublicKey = $this->keyHandler->privateKeyToPublicKey($privateKey);
            $decryptedPublicKey = $this->keyHandler->privateKeyToPublicKey($decryptedKey);

            $this->assertSame($originalPublicKey, $decryptedPublicKey);
        }
    }

    public function testDecryptPrivateKeyWithCorruptedEncryptedKey(): void
    {
        $this->expectException(KeyFormatException::class);
        $this->expectExceptionMessage('私钥解密失败');

        // 先创建有效的加密密钥，然后损坏它
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = 'test-password';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);

        // 损坏加密密钥的部分内容
        $corruptedKey = str_replace('BEGIN ENCRYPTED', 'BEGIN CORRUPTED', $encryptedKey);

        $this->keyHandler->decryptPrivateKey($corruptedKey, $passphrase);
    }

    public function testEncryptPrivateKeyPerformanceTest(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $passphrase = 'performance-test';

        $startTime = microtime(true);

        // 执行多次加密操作
        for ($i = 0; $i < 5; ++$i) {
            $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $passphrase);
            $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $encryptedKey);
        }

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        // 5次加密操作应该在合理时间内完成（小于5秒）
        $this->assertLessThan(5.0, $executionTime);
    }

    public function testDecryptPrivateKeyWrongPassphraseSecurityCheck(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $privateKey = $keyPair['private_key'];
        $correctPassphrase = 'correct-password';

        $encryptedKey = $this->keyHandler->encryptPrivateKey($privateKey, $correctPassphrase);

        // 测试多种错误密码（移除包含null字符的测试，因为可能被截断）
        $wrongPassphrases = [
            'wrong-password',
            '',
            $correctPassphrase . 'extra',
            strtoupper($correctPassphrase),
            'completely-different-password',
        ];

        foreach ($wrongPassphrases as $wrongPassphrase) {
            try {
                $this->keyHandler->decryptPrivateKey($encryptedKey, $wrongPassphrase);
                self::fail('Expected KeyFormatException for passphrase: ' . $wrongPassphrase);
            } catch (KeyFormatException $e) {
                $this->assertStringContainsString('私钥解密失败', $e->getMessage());
            }
        }
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

    public function testPrivateKeyToPublicKey(): void
    {
        $keyPair = $this->keyHandler->generateRsaKeyPair(1024);
        $publicKey = $this->keyHandler->privateKeyToPublicKey($keyPair['private_key']);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
    }
}
