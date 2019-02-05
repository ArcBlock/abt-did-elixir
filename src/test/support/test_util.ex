defmodule AbtDidTest.TestUtil do
  @ed25519 %Mcrypto.Signer.Ed25519{}
  @secp256k1 %Mcrypto.Signer.Secp256k1{}

  def sk_to_pk(:ed25519, sk), do: Mcrypto.sk_to_pk(@ed25519, sk)
  def sk_to_pk(:secp256k1, sk), do: Mcrypto.sk_to_pk(@secp256k1, sk)
end
