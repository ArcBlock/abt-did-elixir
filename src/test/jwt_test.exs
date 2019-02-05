defmodule AbtDidTest.Jwt do
  use ExUnit.Case

  alias AbtDid.Jwt
  alias AbtDid.Type

  test "ed25519 should work" do
    {pk, sk} = Mcrypto.Signer.keypair(%Mcrypto.Signer.Ed25519{})
    did_type = %AbtDid.Type{role_type: :application, key_type: :ed25519, hash_type: :sha3}
    jwt = Jwt.gen_and_sign(did_type, sk)
    assert true === Jwt.verify(jwt, pk)
  end

  test "secp256k1 should work" do
    {pk, sk} = Mcrypto.Signer.keypair(%Mcrypto.Signer.Secp256k1{})
    did_type = %AbtDid.Type{role_type: :account, key_type: :secp256k1, hash_type: :sha3}
    jwt = Jwt.gen_and_sign(did_type, sk)
    assert true === Jwt.verify(jwt, pk)
  end
end
