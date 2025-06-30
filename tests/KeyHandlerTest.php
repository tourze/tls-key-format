<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Tests\KeyHandlerConversionTest;
use Tourze\TLSKeyFormat\Tests\KeyHandlerEncryptionTest;
use Tourze\TLSKeyFormat\Tests\KeyHandlerGenerationTest;

/**
 * 主测试类，集成所有KeyHandler相关测试
 */
class KeyHandlerTest extends TestCase
{
    /**
     * 测试KeyHandler类的存在
     */
    public function test_keyHandlerClassExists(): void
    {
        $this->assertTrue(class_exists(KeyHandler::class));
    }
    
    /**
     * 测试KeyHandler可以被实例化
     */
    public function test_keyHandlerCanBeInstantiated(): void
    {
        $handler = new KeyHandler();
        $this->assertInstanceOf(KeyHandler::class, $handler);
    }
    
    /**
     * 测试相关测试类的存在
     */
    public function test_relatedTestClassesExist(): void
    {
        $this->assertTrue(class_exists(KeyHandlerConversionTest::class));
        $this->assertTrue(class_exists(KeyHandlerEncryptionTest::class));
        $this->assertTrue(class_exists(KeyHandlerGenerationTest::class));
    }
}