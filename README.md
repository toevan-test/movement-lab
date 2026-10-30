# Toevan Evidence Ledger (tamper-evident twin)

This orphan branch, toevan/evidence-dev, is a git-native mirror of Toevan's append-only compliance
evidence ledger for this repository. Each commit adds exactly one evidence run:

    records/<head_sha>/<record_id>.json   the canonical record bytes, VERBATIM

A record of a KIND other than a verdict (change_record, unreviewed_change, control_change, capture_gap,
capture_started, release_record, deployment_record, capture_reading) sits in the same chain and is filed under the sha of its subject commit, or, when it has
none, under _<kind>: records/_capture_started/<record_id>.json. The same applies to attestations/.

To verify independently (Toevan not required):
  1. For each records file, sha256(file bytes) is the run's record_hash.
  2. Each record's prev_record_hash chains to the previous record (by chain_seq).
  3. The git commit DAG is strictly linear (fast-forward only) — a second,
     independent hash chain over the same bytes.

`index/chain-head` holds the latest "<chain_seq> <record_hash>".

    ownership.json                the deployment that owns this branch: its identity, its environment and this
                                  branch's name. Toevan writes to the branch only while this record names the
                                  deployment that is writing, and refuses otherwise. Do not edit it.

    policies/<sha256 hex>.json    the canonical bytes of a repository policy version a record cites;
                                  sha256(file bytes) is the digest the record states

    attestations/<head_sha>/<record_id>.dsse.json

holds the run's SIGNED attestation (an in-toto statement in a DSSE envelope, signed with ECDSA P-256 over
SHA-256). Check one with openssl and Toevan's published public key (saved as toevan.pub), and nothing from Toevan.
Tools: openssl (OpenSSL 3 or later, or the LibreSSL that macOS ships) and the shell utilities sed, wc, tr, cut, cat and printf, in any POSIX shell. Nothing from Toevan is needed.

    ENV=attestations/<head_sha>/<record_id>.dsse.json
    REC=records/<head_sha>/<record_id>.json
    PUB=toevan.pub
    openssl pkey -pubin -in "$PUB" -outform DER | openssl dgst -sha256
    T=$(sed -E 's/.*"payloadType":"([^"]*)".*/\1/' "$ENV")
    sed -E 's/.*"payload":"([^"]*)".*/\1/' "$ENV" | openssl base64 -d -A > statement.json
    sed -E 's/.*"sig":"([^"]*)".*/\1/' "$ENV" | openssl base64 -d -A > sig.der
    { printf 'DSSEv1 %s %s %s ' "${#T}" "$T" "$(wc -c < statement.json | tr -d ' ')"; cat statement.json; } > pae.bin
    openssl dgst -sha256 -verify "$PUB" -signature sig.der pae.bin
    H=$(sed -E 's/.*"record_hash":"sha256:([0-9a-f]{64})".*/\1/' statement.json)
    if [ "$(openssl dgst -sha256 -r "$REC" | cut -d' ' -f1)" = "$H" ]; then echo "record matches the statement"; else echo "RECORD DOES NOT MATCH THE STATEMENT"; fi
    printf 'record %s\n' "$(sed -nE 's/.*"record_id":"([^"]*)".*/\1/p' statement.json)"
    printf 'subject %s\n' "$(sed -nE 's/.*"subject":\[\{"digest":\{"([^"]*)":"([^"]*)"\},"name":"([^"]*)"\}\].*/\3 \1:\2/p' statement.json)"

The signature line prints "Verified OK": the statement was signed by the holder of that key. The key id line
prints the sha256 of the key; it must be the key id Toevan publishes for the key. The last line prints
"record matches the statement" when the record file is the one the signed statement names (the statement carries the sha256 of
the record's bytes). The envelope file is one line of JSON, as Toevan writes it; if it was re-formatted, put it back on one line first.

A record of a kind other than a verdict is signed with the same key and envelope but its own predicate type, for
example https://toevan.com/attestation/change-record/v1 (change-record, unreviewed-change, control-change,
capture-gap, capture-started, release-record, deployment-record, capture-reading), and the same lines check it. It states what Toevan recorded and
binds the statement to the record by its hash.

Toevan's public keys, current and retired, are published at https://moaningly-unusual-camilla.ngrok-free.dev/v1/public/evidence/keys
(each with its key id, the sha256 of the key's DER). `keys/<key_id>.pub` in this branch is
a convenience copy of the key that signed an attestation: trust it only after its key id matches the
published list, never because it sits in this branch. Take toevan.pub from there:

    curl -o toevan.pub https://moaningly-unusual-camilla.ngrok-free.dev/v1/public/evidence/keys/<key_id>.pem

`attestations/<head_sha>/<record_id>.rekor.json` is the transparency-log proof for that
attestation. If the organization anchors in its OWN log, `rekor-logs/<log_id>.pub` carries that
log's public key. Trust it only because sha256 of its SPKI equals the log_id the signed attestation
pins (toevan.transparency_log), never because it sits in this branch; `toevan-audit verify`
checks exactly that.

Do not force-push or delete this branch; configure branch protection to block it.
