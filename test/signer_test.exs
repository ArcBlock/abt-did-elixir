defmodule AbtDidTest.Signer do
  use ExUnit.Case

  alias AbtDid.Signer

  test "ed25519 should work" do
    {pk, sk} = Mcrypto.Signer.keypair(%Mcrypto.Signer.Ed25519{})
    did_type = %AbtDid.Type{role_type: :application, key_type: :ed25519, hash_type: :sha3}
    token = Signer.gen_and_sign(did_type, sk)
    assert true === Signer.verify(token, pk)
  end

  test "secp256k1 should work" do
    {pk, sk} = Mcrypto.Signer.keypair(%Mcrypto.Signer.Secp256k1{})
    did_type = %AbtDid.Type{role_type: :account, key_type: :secp256k1, hash_type: :sha3}
    token = Signer.gen_and_sign(did_type, sk)
    assert true === Signer.verify(token, pk)
  end

  test "overide with extra" do
    {pk, sk} = Mcrypto.Signer.keypair(%Mcrypto.Signer.Secp256k1{})
    did_type = %AbtDid.Type{role_type: :account, key_type: :secp256k1, hash_type: :sha3}

    token = Signer.gen_and_sign(did_type, sk, %{"exp" => nil, "requested" => ["123", "456"]})
    assert true === Signer.verify(token, pk)
    [_, body, _] = String.split(token, ".")
    json = Base.url_decode64!(body, padding: false)
    assert false === String.contains?(json, ~s/"exp"/)
    assert true === String.contains?(json, ~s/"requested":["123","456"]/)
  end
end
