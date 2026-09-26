<?php
// fixtures/mini-poi/plugin.php
//
// Mini-POI plugin. handle() returns an arbitrary value (no
// type contract enforced by the caller). In a benign plugin
// this would return a plain string or array. In a hostile
// plugin it returns an object whose __wakeup will run when
// the cache file is later unserialized.

declare(strict_types=1);

final class MiniPoiPlugin {
    public function handle(string $arg): mixed {
        // BENIGN default: return a plain string. A hostile
        // variant of this file returns an object -- the
        // fixture is paired with fixtures/mini-poi/expected/,
        // which is what a correct audit produces when the
        // plugin is hostile.
        return ['instruction' => $arg];
    }
}