<?php
// fixtures/mini-poi/index.php
//
// Mini-POI fixture: a minimal PHP target that exhibits a
// deserialization object-injection shape similar to DokuWiki
// #4752 (CWE-502). Used by runtime/regression.py to verify that
// the audit framework's expected output passes the enforcement
// primitives (validate-notes + check-skill-loaded).
//
// Shape:
//   - a "plugin" returns an object from its handle() method
//   - the application serializes the plugin's return value into
//     a cache file
//   - a separate request path later unserializes that cache file
//     without [allowed_classes => false]
//
// This file is the application. The plugin is plugin.php.

declare(strict_types=1);

require_once __DIR__ . '/plugin.php';

function mini_poi_store_cache(string $cache_path, string $page_text): void {
    $parser_calls = mini_poi_parse($page_text);
    // VULN: serialize the parser calls including any objects the
    // plugin returned from handle(). No filter on return type.
    file_put_contents($cache_path, serialize($parser_calls));
}

function mini_poi_parse(string $text): array {
    // Naive parser: every line matching /^!plugin!\s*(.*)$/ is
    // routed to the plugin's handle() and the return value
    // becomes a parser call.
    $calls = [];
    foreach (preg_split('/\R/', $text) as $line) {
        if (preg_match('/^!plugin!\s*(.*)$/', $line, $m)) {
            $plugin = new MiniPoiPlugin();
            $ret = $plugin->handle($m[1]);
            // VULN: zero validation of $ret's shape.
            $calls[] = ['plugin', [$ret]];
        }
    }
    return $calls;
}

function mini_poi_serve_page(string $cache_path): void {
    // VULN: unserialize without allowed_classes. The plugin can
    // smuggle an object through the cache file.
    $instructions = unserialize(file_get_contents($cache_path));
    foreach ($instructions as $call) {
        [$tag, $args] = $call;
        // ... rendering elided for fixture brevity
        echo "render: $tag\n";
    }
}

if (PHP_SAPI === 'cli') {
    $text  = $argv[1] ?? '';
    $cache = sys_get_temp_dir() . '/mini_poi_cache.bin';
    mini_poi_store_cache($cache, $text);
    mini_poi_serve_page($cache);
}