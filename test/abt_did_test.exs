defmodule AbtDidTest do
  use ExUnit.Case
  alias AbtDid.Type
  alias AbtDidTest.TestUtil

  doctest AbtDid

  test "Generate did and verify with PK" do
    role = [
      :account,
      :node,
      :device,
      :application,
      :smart_contract,
      :bot,
      :stake,
      :asset,
      :validator,
      :group
    ]

    key = [:ed25519, :secp256k1]
    hash = [:keccak, :sha3, :keccak_384, :sha3_384, :keccak_512, :sha3_512]

    Enum.each(role, fn r ->
      Enum.each(key, fn k ->
        Enum.each(hash, fn h ->
          type = %Type{role_type: r, key_type: k, hash_type: h}

          sk =
            case k do
              :ed25519 -> :crypto.strong_rand_bytes(64)
              :secp256k1 -> :crypto.strong_rand_bytes(32)
            end

          pk = TestUtil.sk_to_pk(k, sk)
          did = AbtDid.sk_to_did(type, sk)

          assert String.length(did) >= 35
          assert true === AbtDid.is_valid?(did)
          assert true === AbtDid.match_pk?(did, pk)
        end)
      end)
    end)
  end
end
