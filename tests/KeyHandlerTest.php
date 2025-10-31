<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * 主测试类，集成所有KeyHandler相关测试
 *
 * @internal
 */
#[CoversClass(KeyHandler::class)]
final class KeyHandlerTest extends TestCase
{
    /**
     * 测试KeyHandler可以被实例化
     */
    public function testKeyHandlerCanBeInstantiated(): void
    {
        $handler = new KeyHandler();
        $this->assertInstanceOf(KeyHandler::class, $handler);
    }

    public function testPrivateKeyToPublicKey(): void
    {
        $handler = new KeyHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->privateKeyToPublicKey('invalid');
    }

    public function testGenerateRsaKeyPair(): void
    {
        $handler = new KeyHandler();
        $result = $handler->generateRsaKeyPair();
        $this->assertArrayHasKey('private_key', $result);
        $this->assertArrayHasKey('public_key', $result);
    }

    public function testGenerateEcKeyPair(): void
    {
        $handler = new KeyHandler();
        $result = $handler->generateEcKeyPair();
        $this->assertArrayHasKey('private_key', $result);
        $this->assertArrayHasKey('public_key', $result);
    }

    public function testEncryptPrivateKey(): void
    {
        $handler = new KeyHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->encryptPrivateKey('invalid', 'password');
    }

    public function testDecryptPrivateKey(): void
    {
        $handler = new KeyHandler();
        $this->expectException(Exception\KeyFormatException::class);
        $handler->decryptPrivateKey('invalid', 'password');
    }
}
