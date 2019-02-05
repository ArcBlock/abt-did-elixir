defmodule AbtDid do
  @moduledoc """
  Generates the DID from secret key or publick key.
  """

  alias AbtDid.TypeBytes
  alias AbtDid.Type, as: DidType
  alias Mcrypto.Hasher.Keccak
  alias Mcrypto.Hasher.Sha3

  @ed25519 %Mcrypto.Signer.Ed25519{}
  @secp256k1 %Mcrypto.Signer.Secp256k1{}

  @keccak %Keccak{}
  @keccak_384 %Keccak{size: 384}
  @keccak_512 %Keccak{size: 512}
  @sha3 %Sha3{}
  @sha3_384 %Sha3{size: 384}
  @sha3_512 %Sha3{size: 512}

  @prefix "did:abt:"

  @doc """
  Generates the DID from secret key.

  ## Examples

      iex> sk = "3E0F9A313300226D51E33D5D98A126E86396956122E97E32D31CEE2277380B83FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{}, sk)
      "did:abt:z1ioGHFYiEemfLa3hQjk4JTwWTQPu1g2YxP"

      iex> sk = "26954E19E8781905E2CF91A18AE4F36A954C142176EE1BC27C2635520C49BC55" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{key_type: :secp256k1}, sk)
      "did:abt:z1Ee1H8g248HqroacmEnZzMYgbhjz1Z2WSvv"

      iex> sk = "26954E19E8781905E2CF91A18AE4F36A954C142176EE1BC27C2635520C49BC55" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{key_type: :secp256k1}, sk, form: :short)
      "z1Ee1H8g248HqroacmEnZzMYgbhjz1Z2WSvv"

      iex> sk = "26954E19E8781905E2CF91A18AE4F36A954C142176EE1BC27C2635520C49BC55" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{key_type: :secp256k1}, sk, encode: false)
      <<0, 33, 228, 184, 246, 38, 116, 137, 126, 215, 93, 240, 247, 53, 110, 130, 198, 249, 166, 74, 92, 19, 243, 204, 12, 211>>
  """
  @spec sk_to_did(DidType.t(), binary(), Keyword.t()) :: String.t()
  def sk_to_did(did_type, sk, opts \\ []) do
    pk = sk_to_pk(did_type.key_type, sk)
    pk_to_did(did_type, pk, opts)
  end

  @doc """
  Generates the DID from publick key.

  Options:
    Key `:form`
        Values `:long` - The returned DID will be prefixed by "did:abt:"
               `:short` - The retuned DID has only DID string.
        `:encode`
        Values `true` - The returned DID will be encoded as Base58.
               `false` - The returned DID will be in binary format and `:form` will be set as `:short`
  """
  @spec pk_to_did(DidType.t(), binary(), Keyword.t()) :: String.t()
  def pk_to_did(did_type, pk, opts \\ []) do
    type_bytes = TypeBytes.struct_to_bytes(did_type)
    <<pk_hash::binary-size(20), _::binary>> = hash(did_type.hash_type, pk)
    <<check_sum::binary-size(4), _::binary>> = hash(did_type.hash_type, type_bytes <> pk_hash)

    encode = Keyword.get(opts, :encode, true)
    form = Keyword.get(opts, :form, :long)

    case encode do
      false ->
        type_bytes <> pk_hash <> check_sum

      true ->
        case form do
          :long -> @prefix <> Multibase.encode!(type_bytes <> pk_hash <> check_sum, :base58_btc)
          :short -> Multibase.encode!(type_bytes <> pk_hash <> check_sum, :base58_btc)
        end
    end
  end

  @doc """
  Verifies if a public key and a DID match with each other.
  """
  @spec match_pk?(String.t(), binary()) :: boolean()
  def match_pk?(@prefix <> did, pk), do: match_pk?(did, pk)

  def match_pk?(did, pk) do
    <<type_bytes::binary-size(2), _::binary>> = Multibase.decode!(did)
    did_type = TypeBytes.bytes_to_struct(type_bytes)
    pk_to_did(did_type, pk) == @prefix <> did
  rescue
    _ -> false
  end

  @doc """
  Verifies if a DID is valid by checking the checksum.

  ## Examples

      iex> AbtDid.is_valid?("did:abt:z1muQ3xqHQK2uiACHyChikobsiY5kLqtShA")
      true

      iex> AbtDid.is_valid?("z1muQ3xqHQK2uiACHyChikobsiY5kLqtShA")
      true

      iex> AbtDid.is_valid?("z2muQ3xqHQK2uiACHyChikobsiY5kLqtShA")
      false

      iex> AbtDid.is_valid?("z1muQ3xqHQK2uiACHyChikobsiY5kLqtSha")
      false
  """
  def is_valid?(@prefix <> did), do: is_valid?(did)

  def is_valid?(did) do
    <<type_bytes::binary-size(2), pk_hash::binary-size(20), actual::binary-size(4)>> =
      Multibase.decode!(did)

    did_type = TypeBytes.bytes_to_struct(type_bytes)

    <<expected::binary-size(4), _::binary>> = hash(did_type.hash_type, type_bytes <> pk_hash)
    expected == actual
  rescue
    _ -> false
  end

  @doc """
  Gets the DID type information from the DID.

  ## Examples

      iex> AbtDid.get_did_type("did:abt:z1muQ3xqHQK2uiACHyChikobsiY5kLqtShA")
      %AbtDid.Type{hash_type: :sha3, key_type: :ed25519, role_type: :account}

      iex> AbtDid.get_did_type("z1muQ3xqHQK2uiACHyChikobsiY5kLqtShA")
      %AbtDid.Type{hash_type: :sha3, key_type: :ed25519, role_type: :account}
  """
  @spec get_did_type(String.t()) :: DidType.t()
  def get_did_type(@prefix <> did), do: get_did_type(did)

  def get_did_type(did) do
    <<type_bytes::binary-size(2), _::binary>> = Multibase.decode!(did)
    TypeBytes.bytes_to_struct(type_bytes)
  end

  ############   private functiosn    ############

  defp sk_to_pk(:ed25519, sk), do: Mcrypto.sk_to_pk(@ed25519, sk)
  defp sk_to_pk(:secp256k1, sk), do: Mcrypto.sk_to_pk(@secp256k1, sk)

  defp hash(:keccak, data), do: Mcrypto.hash(@keccak, data)
  defp hash(:sha3, data), do: Mcrypto.hash(@sha3, data)
  defp hash(:keccak_384, data), do: Mcrypto.hash(@keccak_384, data)
  defp hash(:sha3_384, data), do: Mcrypto.hash(@sha3_384, data)
  defp hash(:keccak_512, data), do: Mcrypto.hash(@keccak_512, data)
  defp hash(:sha3_512, data), do: Mcrypto.hash(@sha3_512, data)
end
