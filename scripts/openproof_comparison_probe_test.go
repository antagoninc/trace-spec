package main

// This adapter composes native upstream checks for TRACE's reference profile.
// It is copied beside the pinned, unmodified upstream Go implementation.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// encoding/json agrees with JCS only in this deliberately restricted domain.
// The fixture requests contain ASCII strings and unsigned safe integers.
func fixtureJSON(v any) {
	switch x := v.(type) {
	case nil, bool:
	case json.Number:
		need(num(x) <= 9007199254740991)
	case string:
		for _, r := range x {
			need(r >= 32 && r <= 126 && !strings.ContainsRune("<>&", r))
		}
	case []any:
		for _, item := range x {
			fixtureJSON(item)
		}
	case map[string]any:
		for k, item := range x {
			fixtureJSON(k)
			fixtureJSON(item)
		}
	default:
		panic("unsupported fixture JSON type")
	}
}

func referenceProbe(input map[string]any) (out map[string]any) {
	out = map[string]any{"verdict": "approval-unconfirmed"}
	phase := "resolution"
	defer func() {
		if failure := recover(); failure != nil {
			if failure != "invalid evidence" {
				panic(failure)
			}
			out["rejected_at"] = phase
			switch phase {
			case "trust":
				out["verdict"] = "trust-unverified"
			case "approval", "passkey":
				out["verdict"] = "approval-not-attributable"
			default:
				panic(failure) // Harness errors must fail the test process.
			}
		}
	}()
	record := obj(input["record"])
	store := obj(input["store"])
	refs := arr(record["references"])
	need(len(refs) == 1)
	ref := obj(refs[0])
	need(str(ref["rel"]) == "approval-outcome")
	need(str(ref["resolver"]) == str(store["resolver"]))
	entryValue, found := obj(store["entries"])[str(ref["id"])]
	if !found {
		return out
	}
	entry := obj(entryValue)
	q := request(entry["request"])
	fixtureJSON(q)
	encoded, err := json.Marshal(q)
	need(err == nil)
	h := sha256.Sum256(encoded)
	if str(ref["digest"]) != "sha256:"+hex.EncodeToString(h[:]) {
		out["verdict"] = "approval-contradicted"
		return out
	}
	phase = "trust"
	t := trust(signed(store["signed_trust"], input["root_key"], "witness-trust/1"), num(input["now"]))
	phase = "approval"
	a := approval(obj(q["approval"])["payload"])
	d := digest("document-approval/1", a)
	need(str(ref["id"]) == "openproof/approval/"+d)
	issuer := str(a["authority"])
	need((issuer == str(t["authority"]) || contains(t["previous_authorities"], issuer)) &&
		!contains(t["revoked_authorities"], issuer))
	signed(q["approval"], issuer, "document-approval/1")
	need(hash(str(q["content"])) == str(a["content_sha256"]))
	need(str(a["receiver"]) == str(t["receiver"]))
	phase = "passkey"
	if entry["receipt"] == nil {
		// TRACE's stricter approval-only profile requires a configured passkey
		// even without a receiver-authenticated sequence. Call its native
		// assertion verifier directly; never invent a receipt sequence.
		if k, configured := t["owner_passkey"]; configured {
			verifyAssertion(obj(q["owner_assertion"]), obj(k), d)
		} else {
			_, present := q["owner_assertion"]
			need(!present)
		}
		out["verdict"] = "approved-not-executed"
		return out
	}
	// The unmodified CLI's verify function authenticates receipt history,
	// enrollment sequence, temporal bounds and checkpoint together.
	phase = "history"
	packageValue := map[string]any{
		"version": version, "requests": []any{q},
		"receipts": []any{entry["receipt"]}, "checkpoint": entry["checkpoint"],
	}
	out["history"] = verify(t, entry["checkpoint"], packageValue, num(input["now"]))
	out["verdict"] = "approval-confirmed-and-executed"
	return out
}

func TestTRACEReferenceProbe(t *testing.T) {
	input := read(os.Getenv("OPENPROOF_COMPARISON_INPUT"))
	result := referenceProbe(obj(input))
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("TRACE_PROBE=" + string(encoded))
}
