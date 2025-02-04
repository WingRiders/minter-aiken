use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Finite}
use cardano/assets.{PolicyId}
use cardano/script_context.{ScriptContext}
use cardano/transaction.{Transaction}

validator minter(
  _collection_id: ByteArray,
  authority: VerificationKeyHash,
  end_date: Option<Int>,
) {
  // Each token policy from this minter is uniquely identified by:
  // * the collection id byte array
  // * the minting authority verification key hash
  // * the optional end date
  //
  // The authority must sign any minting/burning transaction with the tokens.
  // All minting/burning must happen before the end date if it's set.
  mint(_redeemer: Data, _policy_id: PolicyId, transaction: Transaction) {
    // Authority must sign the transaction
    let signed_by_authority =
      list.any(transaction.extra_signatories, fn(sig) { sig == authority })

    let end_date_correct =
      when end_date is {
        Some(upper_bound) -> {
          expect Finite(upper_bound_tx) =
            transaction.validity_range.upper_bound.bound_type
          // Tokens must be minted before the end date
          upper_bound_tx < upper_bound
        }
        None -> True
      }

    and {
      signed_by_authority,
      end_date_correct,
    }
  }

  else(_ctx: ScriptContext) {
    fail
  }
}
