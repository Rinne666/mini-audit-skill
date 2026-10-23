<?php
// Fixture target: a miniature service with four claim shapes.
//
// The point of this fixture is that the four shapes produce four
// different adjudication verdicts. A framework that can only ever
// produce "report" is not an adjudication framework.
//
//   Shape A — the claim holds, and would be accepted.
//            An external authentication extension may answer with an
//            empty body. The implementation instead rewrites the
//            stored password with the value the unauthenticated client
//            presented, then verifies the client against the hash it
//            just wrote.
//
//   Shape B — the claim does not hold.
//            A claim that "the share download path does not check the
//            share token". The path does check it, at a line the claim
//            did not mention.
//
//   Shape C — the claim needs evidence that source cannot settle.
//            A claim that "the login path is not rate limited". The
//            limiter permits every attempt when no per-minute limit
//            is configured, and the configured value comes from the
//            environment, so whether the limit binds is a deployment
//            fact that this source cannot settle.
//
//   Shape D — the claim was true and is now fixed.
//            A path that used to skip the session binding. The fix is
//            present in the current source.

declare(strict_types=1);

final class Store
{
    /** @var array<string, array{password_hash: string, is_admin: bool}> */
    private array $users = [];

    /** @var array<string, string> */
    private array $sessions = [];

    public function find(string $username): ?array
    {
        return $this->users[$username] ?? null;
    }

    public function save(string $username, string $passwordHash, bool $isAdmin): void
    {
        $this->users[$username] = [
            'password_hash' => $passwordHash,
            'is_admin' => $isAdmin,
        ];
    }

    public function countAdmins(): int
    {
        $count = 0;
        foreach ($this->users as $user) {
            if ($user['is_admin']) {
                $count++;
            }
        }
        return $count;
    }

    public function newSession(string $token, string $username): void
    {
        $this->sessions[$token] = $username;
    }

    public function sessionUser(string $token): ?string
    {
        return $this->sessions[$token] ?? null;
    }
}

/**
 * The external authentication extension. It answers with the payload it
 * wants stored, or an empty string when it has no opinion about the
 * login attempt.
 */
interface ExternalAuth
{
    public function authenticate(string $username, string $password): string;
}

final class AuthService
{
    public function __construct(
        private Store $store,
        private ExternalAuth $external,
        private RateLimiter $limiter,
    ) {
    }

    /**
     * Shape A. The extension's empty answer is read as "please set this
     * password" instead of "I have no opinion".
     */
    public function login(string $username, string $password): bool
    {
        $this->limiter->recordAttempt($username);
        if (!$this->limiter->allow($username)) {
            return false;
        }

        $answer = $this->external->authenticate($username, $password);

        if ($answer === '') {
            $user = $this->store->find($username);
            if ($user === null) {
                return false;
            }
            // DEFECT: the presented password is written to the store and
            // then verified against the hash that was just created from
            // it, so any password succeeds.
            $this->store->save($username, password_hash($password, PASSWORD_DEFAULT), $user['is_admin']);
            return true;
        }

        $user = $this->store->find($username);
        if ($user === null) {
            return false;
        }
        return password_verify($password, $user['password_hash']);
    }

    /**
     * The pre-login probe. An empty extension answer means "no opinion",
     * so the probe must not treat the account as authenticated.
     */
    public function probe(string $username, string $password): bool
    {
        $answer = $this->external->authenticate($username, $password);
        if ($answer === '') {
            return false;
        }
        return true;
    }
}

final class AdminService
{
    public function __construct(
        private Store $store,
        private ExternalAuth $external,
    ) {
    }

    /**
     * The admin plane. Refuses the same empty extension answer that
     * AuthService::login accepts. This is one side of the divergence.
     */
    public function login(string $username, string $password): bool
    {
        $answer = $this->external->authenticate($username, $password);
        if ($answer === '') {
            return false;
        }
        $user = $this->store->find($username);
        if ($user === null) {
            return false;
        }
        return password_verify($password, $user['password_hash']);
    }
}

final class ShareService
{
    public function __construct(
        private Store $store,
    ) {
    }

    /**
     * Shape B. A claim says this path does not check the share token.
     * It does check it, right here, before the session is looked up.
     */
    public function download(string $shareToken, string $sessionToken): bool
    {
        $expected = $this->expectedTokenFor($shareToken);
        if (!hash_equals($expected, $shareToken)) {
            return false;
        }
        if ($this->store->sessionUser($sessionToken) === null) {
            return false;
        }
        return true;
    }

    private function expectedTokenFor(string $shareToken): string
    {
        return hash('sha256', $shareToken);
    }
}

/**
 * A per-minute request limiter.
 *
 * Shape C. Whether the limit binds depends on a value read from the
 * environment, so the source cannot settle it.
 */
final class RateLimiter
{
    /** @var array<string, int> */
    private array $attempts = [];

    public function __construct(
        private int $limitPerMinute,
    ) {
    }

    public static function fromEnvironment(): self
    {
        // The effective limit depends on a deployment value.
        $configured = getenv('APP_RATE_LIMIT_PER_MINUTE');
        $limit = ($configured === false || $configured === '') ? 0 : (int) $configured;
        return new self($limit);
    }

    public function recordAttempt(string $key): void
    {
        $this->attempts[$key] = ($this->attempts[$key] ?? 0) + 1;
    }

    public function allow(string $key): bool
    {
        if ($this->limitPerMinute <= 0) {
            // A limit of zero means "no limit configured".
            return true;
        }
        return ($this->attempts[$key] ?? 0) < $this->limitPerMinute;
    }
}

final class LegacySessionService
{
    /**
     * Shape D. This path used to accept a session without checking
     * that it was bound to the credential it was issued against. The
     * binding is now enforced, and the fix is visible in the source.
     */
    public function authenticate(string $sessionToken, string $currentCredential): bool
    {
        $boundCredential = $this->credentialForSession($sessionToken);
        if ($boundCredential === null) {
            return false;
        }
        // FIXED: the session is bound to the credential it was issued
        // against, so a rotated credential ends the session.
        if (!hash_equals($boundCredential, $currentCredential)) {
            return false;
        }
        return true;
    }

    private function credentialForSession(string $sessionToken): ?string
    {
        return hash('sha256', $sessionToken);
    }
}
