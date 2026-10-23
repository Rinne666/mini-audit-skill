<?php
// Fixture target: a miniature service with two disclosure-relevant shapes.
//
// Shape A — the "send" candidate.
//   An external authentication extension may answer with an empty body.
//   That answer means "no opinion", so the stored credential must be
//   left untouched. This implementation instead rewrites the stored
//   password with the value the unauthenticated client presented, and
//   then verifies the client against the hash it just wrote.
//
// Shape B — the "closed" candidate.
//   A bootstrap check decides whether the service is already
//   initialised. When the lookup fails, it answers "not initialised"
//   and lets the anonymous setup endpoint create the first
//   administrator.
//
// Both shapes are reduced from a real project so the fixture can lock
// the triage format: the premise classification, the divergence
// evidence, and the subject rewriting all differ between them.

declare(strict_types=1);

final class Store
{
    /** @var array<string, array{password_hash: string, is_admin: bool}> */
    private array $users = [];

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
    ) {
    }

    /**
     * Shape A. The extension's empty answer is read as "please set this
     * password" instead of "I have no opinion".
     *
     * The admin plane (AdminService::login) refuses the same empty
     * answer, and the pre-login probe (AuthService::probe) refuses it
     * too. Only this path rewrites the stored credential.
     */
    public function login(string $username, string $password): bool
    {
        $answer = $this->external->authenticate($username, $password);

        if ($answer === '') {
            // The extension had no opinion. The stored credential must
            // survive untouched, and the presented password must be
            // checked against the unchanged stored hash.
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

final class SetupService
{
    private const MIN_DELAY_US = 1_000_000;

    private int $lastCheck = 0;

    public function __construct(
        private Store $store,
        private bool $queryFails = false,
    ) {
    }

    /**
     * Shape B. When the administrator lookup fails, the answer is
     * "not initialised" rather than "unknown", and the setup endpoint
     * is allowed to create the first administrator.
     *
     * The state this method reports is per-process: it is not shared
     * with other instances, and it is not persisted.
     */
    public function isInitialised(): bool
    {
        $now = hrtime(true);
        if ($now - $this->lastCheck < self::MIN_DELAY_US) {
            return false;
        }
        $this->lastCheck = $now;

        if ($this->queryFails) {
            // DEFECT: an unknown administrator state is reported as
            // "no administrator exists".
            return false;
        }

        return $this->store->countAdmins() > 0;
    }

    /**
     * The anonymous setup endpoint. Creates the first administrator.
     */
    public function createFirstAdmin(string $username, string $password): bool
    {
        if ($this->isInitialised()) {
            return false;
        }
        $this->store->save($username, password_hash($password, PASSWORD_DEFAULT), true);
        return true;
    }
}
