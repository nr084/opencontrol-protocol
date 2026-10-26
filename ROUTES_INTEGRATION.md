# Route and DNS application contract

Wire state and OS state are separate. `RouteState` validates a complete message
before commit, deduplicates, and handles START mark / add-touch / END sweep. Empty
START|END withdraws the previous set. Additive empty messages need not withdraw it.
Client bit2 (safeLan) is status only; bit0+bit3 generates two default-covering /1s.
Unknown bits are preserved without policy. Endpoint/S2S profile interprets only0/1;
client safeLan/full-tunnel semantics are not inferred for S2S.

`RouteApplications` stages desired state per epoch, tracks acknowledged resources
and serializes application plans. Equal prefixes are first-owner-wins; nested
prefixes are distinct. After a competing owner withdraws, an unchanged advertisement
can generate a new application plan. No automatic traffic failover is promised.
The caller may also retry plans independently of advertisements.

```rust,ignore
let notice = applications.receive(epoch, &routes)?;
// Even !notice.logical_changed may require recovery of external state.
if let Some(plan) = applications.begin_plan(epoch)? {
    let mut results = vec![false; plan.operations().len()];
    for (i, operation) in plan.operations().iter().enumerate() {
        results[i] = platform.apply(operation).is_ok();
        if !results[i] { break; } // in particular, never bypass failed endpoint protection
    }
    let status_ok = platform.record_safe_lan_status(plan.safe_lan_status()).is_ok();
    applications.acknowledge(plan.id(), &results, status_ok)?;
}
```

The executable [client_routes example](crates/opencontrol-protocol/examples/client_routes.rs)
uses a mock platform and tests partial failures; it never changes the OS.
Do not mutate OS resources outside the same serialized adapter without reconciling
its ownership journal. Register foreign prefixes from a trusted OS snapshot with
`register_external`; they will not be removed by session cleanup. If external
software changes an acknowledged resource, reconcile the actual snapshot before
resuming plans (cancel/drain old application callbacks before rebuilding the
coordinator under the adapter lock). This in-memory
coordinator is not a persistent crash-recovery journal.

Capture endpoint gateway/interface before full tunnel. A plan adds endpoint/32
via that original uplink before adding /1s. Without known uplink protection a
full-tunnel plan returns UnsupportedCapability. Existing foreign endpoint routes
must be verified by the adapter to preserve reachability before registering them.
On split transition owned /1s are removed; endpoint/32 can remain until disconnect.
On cancellation/reconnect retain the old epoch's resource journal; `withdraw`,
execute/acknowledge cleanup with retry, then `forget`. An error removing a route
must not drop ownership. Partial successful adds are recorded even when the next
operation fails; retry or explicitly withdraw/rollback the recorded resources.

## DNS belongs to the platform

No DNS file writes occur in this crate. An adapter should implement this sequence:

1. Under its resolver lock, capture original bytes, identity/version and ownership.
   Persist a recovery record atomically before replacing anything.
2. Prepare the complete VPN resolver in a separate file, validate it, flush and
   atomically replace the destination; record its identity/hash. On any write or
   rename failure keep the original and recovery record, and return failure.
3. On cleanup compare the current resolver identity/hash with the last owned write.
   If another application changed it, preserve that external state and report a
   conflict; do not blindly overwrite it with an old backup.
4. Restore using a fresh temporary file and atomic replace. Verify restored bytes
   before deleting the backup/recovery record. Failed or partial restore retains
   the record for retry. SIGKILL requires an adapter-owned startup reconciler.

```text
restore(record):
  lock resolver
  if current != record.last_owned: return Conflict (keep backup)
  prepare_and_flush(record.original) or return Retry (keep backup)
  atomic_replace() or return Retry (keep backup)
  verify_original() or return Retry (keep backup)
  delete_recovery_record()
```

Use the platform's native transactional resolver API when available. A network
`Unchanged` result does not prove that resolver, routes or TUN operations succeeded.
