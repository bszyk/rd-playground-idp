<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitbc98c8829083f4d48d5fc1ca8f0fc8b7
{
    public static $prefixLengthsPsr4 = array (
        'R' => 
        array (
            'RD\\' => 3,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'RD\\' => 
        array (
            0 => __DIR__ . '/../..' . '/includes',
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitbc98c8829083f4d48d5fc1ca8f0fc8b7::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitbc98c8829083f4d48d5fc1ca8f0fc8b7::$prefixDirsPsr4;

        }, null, ClassLoader::class);
    }
}
