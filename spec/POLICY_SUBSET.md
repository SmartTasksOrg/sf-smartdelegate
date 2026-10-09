# The portable Cedar subset

Policies are written in [Cedar](https://www.cedarpolicy.com). The Rust port
compiles `policies/*.cedar` into `policies.json` with the Cedar library itself
(`smartdelegate bundle compile`). `policies.json` is Cedar's own JSON policy form,
keyed by policy id, plus the hash of each source file:

```json
{"format": "cedar-json/1",
 "sources": {"policies/crm.cedar": "<sha256>"},
 "policies": {"support-read-customer": {"effect": "permit", "principal": {...}, "action": {...},
              "resource": {...}, "conditions": [...], "annotations": {...}}}}
```

Every port evaluates that JSON directly. No port other than Rust parses Cedar
text, and no port other than Rust needs Rust at run time.

What "evaluate" means is not left to each port's reading of the Cedar
documentation. `conformance/eval/cases.json` holds 91 policies with requests,
and the expected answer in each case **was produced by the real Cedar engine**
(`smartdelegate spec eval-gen`). The Rust port's test suite re-checks the file
against Cedar on every run, so it cannot drift. A port is correct when it
gives Cedar's answer on every case.

## In the subset

| | |
|---|---|
| Effects | `permit`, `forbid` |
| Scope | `principal`, `action`, `resource` with `==`, `in`, `is`, `is … in`; `action in [list]` |
| Conditions | `when`, `unless`, any number |
| Literals | booleans, longs, strings, entity references, sets, records |
| Variables | `principal`, `action`, `resource`, `context` |
| Boolean | `&&`, `\|\|`, `!`, `if … then … else` |
| Comparison | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| Arithmetic | `+`, `-`, `*`, unary `-` (64-bit; overflow is an error) |
| Hierarchy | `in` (entity or set of entities), `is`, `is … in` |
| Sets | `contains`, `containsAll`, `containsAny`, `isEmpty` |
| Attributes | `.`, `has` on entities and records |
| Strings | `like` with `*` |
| Annotations | any; `@id`, `@row_filter`, `@rate_limit`, `@require_approval` are used |

## Outside the subset

Refused when the bundle loads (`policy_parse`), never guessed at:

- extension types and functions: `ip`, `decimal`, `datetime`, `duration`
- entity tags: `hasTag`, `getTag`
- policy templates and slots
- extension values in entities or context (`{"__extn": …}`)

Schema validation is not part of any port: policies are not type-checked.

## Semantics a port must get right

All are covered by eval cases.

1. A policy whose condition errors is skipped and reported, permit or forbid alike. (The engine above this then turns an erroring forbid into a deny; that is SmartDelegate's rule, not Cedar's.)
2. A satisfied forbid denies. Otherwise a satisfied permit allows. Otherwise deny.
3. `&&` and `||` short-circuit, but the side that is evaluated must be a boolean.
4. `==` between different types is `false`. `<` between non-longs is an error. Strings have no order.
5. Sets ignore order and duplicates. Records compare by key.
6. An entity that is not in the store has no attributes: `.` errors, `has` is `false`. It is `in` only itself.
7. `in` is reflexive and transitive over `parents`.
8. A condition must evaluate to a boolean; anything else is an error.
9. JSON lists in entities and context are sets. `{"__entity": {"type", "id"}}` is an entity reference. Floats and nulls are not Cedar values and are rejected.
