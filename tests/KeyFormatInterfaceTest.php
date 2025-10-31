<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\KeyFormatInterface;

/**
 * @internal
 */
#[CoversClass(KeyFormatInterface::class)]
final class KeyFormatInterfaceTest extends TestCase
{
    public function testInterfaceStructure(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);

        self::assertTrue($reflection->isInterface());

        $expectedMethods = [
            'pemToDer',
            'derToPem',
            'extractFromPem',
            'isValidPem',
            'isValidDer',
        ];

        foreach ($expectedMethods as $methodName) {
            self::assertTrue(
                $reflection->hasMethod($methodName),
                sprintf('Interface should have method %s', $methodName)
            );
        }
    }

    public function testPemToDerMethodSignature(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);
        $method = $reflection->getMethod('pemToDer');

        self::assertTrue($method->isPublic());
        self::assertCount(1, $method->getParameters());

        $parameter = $method->getParameters()[0];
        self::assertSame('pemData', $parameter->getName());

        $type = $parameter->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame('string', $type->getName());
        self::assertFalse($type->allowsNull());

        $returnType = $method->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame('string', $returnType->getName());
        self::assertFalse($returnType->allowsNull());
    }

    public function testDerToPemMethodSignature(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);
        $method = $reflection->getMethod('derToPem');

        self::assertTrue($method->isPublic());
        self::assertCount(2, $method->getParameters());

        $derDataParam = $method->getParameters()[0];
        self::assertSame('derData', $derDataParam->getName());
        $derDataType = $derDataParam->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $derDataType);
        self::assertSame('string', $derDataType->getName());

        $typeParam = $method->getParameters()[1];
        self::assertSame('type', $typeParam->getName());
        $typeParamType = $typeParam->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $typeParamType);
        self::assertSame('string', $typeParamType->getName());

        $returnType = $method->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame('string', $returnType->getName());
    }

    public function testExtractFromPemMethodSignature(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);
        $method = $reflection->getMethod('extractFromPem');

        self::assertTrue($method->isPublic());
        self::assertCount(1, $method->getParameters());

        $parameter = $method->getParameters()[0];
        self::assertSame('pemData', $parameter->getName());
        $type = $parameter->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame('string', $type->getName());

        $returnType = $method->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame('array', $returnType->getName());
    }

    public function testIsValidPemMethodSignature(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);
        $method = $reflection->getMethod('isValidPem');

        self::assertTrue($method->isPublic());
        self::assertCount(1, $method->getParameters());

        $parameter = $method->getParameters()[0];
        self::assertSame('pemData', $parameter->getName());
        $type = $parameter->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame('string', $type->getName());

        $returnType = $method->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame('bool', $returnType->getName());
    }

    public function testIsValidDerMethodSignature(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);
        $method = $reflection->getMethod('isValidDer');

        self::assertTrue($method->isPublic());
        self::assertCount(1, $method->getParameters());

        $parameter = $method->getParameters()[0];
        self::assertSame('derData', $parameter->getName());
        $type = $parameter->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame('string', $type->getName());

        $returnType = $method->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame('bool', $returnType->getName());
    }

    public function testInterfaceConstants(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);

        // 接口本身不应该定义常量，但可以验证这一点
        self::assertCount(0, $reflection->getConstants());
    }

    public function testInterfaceProperties(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);

        // 接口不应该有属性
        self::assertCount(0, $reflection->getProperties());
    }

    public function testInterfaceAbstraction(): void
    {
        $reflection = new \ReflectionClass(KeyFormatInterface::class);

        // 验证所有方法都是抽象的
        foreach ($reflection->getMethods() as $method) {
            self::assertTrue($method->isAbstract());
        }
    }
}
