<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Tests\CertificateHandlerParsingTest;
use Tourze\TLSKeyFormat\Tests\CertificateHandlerValidationTest;

/**
 * 主测试类，集成所有CertificateHandler相关测试
 */
class CertificateHandlerTest extends TestCase
{
    /**
     * 测试CertificateHandler类的存在
     */
    public function test_certificateHandlerClassExists(): void
    {
        $this->assertTrue(class_exists(CertificateHandler::class));
    }
    
    /**
     * 测试CertificateHandler可以被实例化
     */
    public function test_certificateHandlerCanBeInstantiated(): void
    {
        $handler = new CertificateHandler();
        $this->assertInstanceOf(CertificateHandler::class, $handler);
    }
    
    /**
     * 测试相关测试类的存在
     */
    public function test_relatedTestClassesExist(): void
    {
        $this->assertTrue(class_exists(CertificateHandlerParsingTest::class));
        $this->assertTrue(class_exists(CertificateHandlerValidationTest::class));
    }
}