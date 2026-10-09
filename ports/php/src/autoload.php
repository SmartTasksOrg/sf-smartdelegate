<?php
// Minimal PSR-4 autoloader so the library works without Composer:
//   require __DIR__ . '/src/autoload.php';
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'SmartDelegate\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
