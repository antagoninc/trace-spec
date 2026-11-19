# OpenProof fixture comparison

This optional comparison runs the five fixtures from TRACE PR #660 through the
pinned Python assessment and a Go adapter that calls OpenProof's native checks.
The upstream full-history CLI also runs for the two fixtures with receipts.

| Fixture | Python and Go adapter outcome | Full-history CLI |
| --- | --- | --- |
| 01 executed | approval-confirmed-and-executed | accepts |
| 02 altered content | approval-contradicted | rejects |
| 03 approval without receipt | approved-not-executed | outside input contract |
| 04 unresolved reference | approval-unconfirmed | outside input contract |
| 05 authority outside trust | approval-not-attributable | outside input contract |

## Reproduce

Use Python 3.12 and a Go toolchain supporting Go 1.20. The measured run used
Python 3.12.14 and Go 1.23.12 on Linux. Go modules are fetched using the pinned
upstream go.mod/go.sum and readonly module mode.

Check out antagoninc/openproof at
`d85c24a1ec9228de7c4876904f260a0093312b70`. Use a clean tracked checkout with
no untracked files under reference/go-witness. Retain TRACE fixture revision
`afc6e9acdb35a3f2f24f3aaf192ac802a91b0211` in local Git history. Install TRACE's
hash-locked development dependencies followed by its editable package.

```sh
python -m pip install --require-hashes -r requirements/dev.txt
python -m pip install --no-deps -e .
python scripts/compare_openproof_verifier.py \
  --upstream /path/to/openproof \
  --go /absolute/path/to/go \
  --output comparison.json
```

The runner checks each JSON fixture and the Python assessment against the pinned
TRACE revision. It runs upstream Go tests and builds the original CLI. It also
copies tracked upstream Go package files to a temporary directory, adds
openproof_comparison_probe_test.go, and executes that test through Go. Native
upstream source files are copied byte for byte. The adapter's source hash, runner
hash, input hashes, CLI binary hash, toolchain version and results are recorded.
The command fails on disagreement, unexpected native panics, build/runtime errors,
or a missing negative-control rejection.

The three negative controls use case 03 with a different valid root key, a damaged
approval signature, and a damaged passkey signature. The latter two use unsigned
diagnostic copies of the reference with its digest recomputed to reach the
native signature checks. They do not claim to verify modified TRACE signatures.
Each control asserts its rejection stage as well as the verdict. In three local
mutation trials, disabling the corresponding adapter call caused its own control
to fail. The original signed fixtures are retained.

## Scope

The Go adapter supplies reference lookup, digest comparison, check ordering and
verdict labels. Root trust, Ed25519 approval signatures and WebAuthn assertions
are checked by the pinned upstream Go functions. For case 03, the adapter follows
TRACE's stricter approval-only profile by calling verifyAssertion directly when
a passkey is configured. It invents no receipt sequence. Case 05 must reject at
the authority stage before reaching a passkey check. Case 04 exercises lookup
only and reaches no native cryptographic check.

Go encoding/json is used for the reference digest only after asserting that the
request contains ASCII printable strings excluding HTML-escaped characters,
unsigned safe integers, booleans, nulls and their containers. Key ordering and
string/number encodings then agree with RFC 8785 on these inputs. This adapter
does not implement general RFC 8785 support.

The full-history CLI checks stronger history/temporal conditions than the
Python fixture assessment. Two matching accept/reject results do not prove
general equivalence or identical rejection reasons. All assessments use an
explicit historical time from the signed fixture checkpoint. They establish no
current freshness, external root/checkpoint custody, hardware protection or
physical effects. Go and Python share upstream project authorship. This run
adds implementation diversity and reviewer-operated measurements.

The recorded result is in openproof-comparison-results.json. The comparison is
optional and requires the external pinned checkout and Go toolchain.
