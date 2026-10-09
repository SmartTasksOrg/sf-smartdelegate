<?php
declare(strict_types=1);

namespace SmartDelegate;

/** Internal: who a request is made for, as read from a verified token (or a trusted chain). */
final class Principal
{
    /**
     * @param list<string>          $chain  agents, root first
     * @param list<string>          $anc    ids of the tokens this one was derived from
     * @param list<JsonObject>|null $groups live group membership [{type, id}] that replaces entities.json
     *                                      for this user, or null to use entities.json
     */
    public function __construct(
        public string $user,
        public array $chain,
        public mixed $tenant,
        public mixed $task,
        public ?string $jti,
        public array $anc,
        public ?Cap $cap,
        public int|BigInt $exp,
        public mixed $role = null,
        public ?array $groups = null,
    ) {
    }

    /** Budgets of ancestor tokens, as carried by the token's `lim` claim: {token id: {currency: amount}}. */
    public ?JsonObject $lim = null;

    public function leaf(): string
    {
        return $this->chain ? $this->chain[count($this->chain) - 1] : '';
    }

    public function toJson(): JsonObject
    {
        return new JsonObject(['user' => $this->user, 'agent' => $this->leaf(), 'chain' => $this->chain, 'tenant' => $this->tenant,
            'task' => $this->task, 'role' => $this->role, 'token_id' => $this->jti]);
    }

    public static function of(JsonObject $claims): self
    {
        $anc = $claims->get('anc');
        $p = new self(Tokens::userOf($claims), Tokens::chainOf($claims), $claims->get('tnt'), $claims->get('task'),
            $claims->get('jti'), is_array($anc) ? $anc : [], Cap::fromJson($claims->get('cap')), $claims->get('exp'),
            $claims->get('role'), $claims->get('grp'));
        $lim = $claims->get('lim');
        $p->lim = $lim instanceof JsonObject ? $lim : null;
        return $p;
    }
}
