defmodule AbtDid do
  @moduledoc """
  ArcBlock DID (decentralized identification) Authentication Protocol is an open protocol that provides a secure decentralized authentication mechanism by using asymmetric cryptography technology.

  This module contains methods to generate the DID from secret key or publick key or publick key hash.
  """

  alias AbtDid.TypeBytes
  alias AbtDid.Type, as: DidType
  alias Mcrypto.Hasher.Keccak
  alias Mcrypto.Hasher.Sha3
  alias Mcrypto.Hasher.Sha2

  @ed25519 %Mcrypto.Signer.Ed25519{}
  @secp256k1 %Mcrypto.Signer.Secp256k1{}

  @keccak %Keccak{}
  @keccak_384 %Keccak{size: 384}
  @keccak_512 %Keccak{size: 512}
  @sha3 %Sha3{}
  @sha3_384 %Sha3{size: 384}
  @sha3_512 %Sha3{size: 512}
  @sha2 %Sha2{round: 1}

  @prefix "did:abt:"

  @spec sk_to_wallet(DidType.t(), binary(), Keyword.t()) :: String.t()
  def sk_to_wallet(did_type, sk, opts \\ []) do
    pk = sk_to_pk(did_type.key_type, sk)
    did = pk_to_did(did_type, pk, opts)

    %{
      sk: sk,
      pk: pk,
      address: did
    }
  end

  @doc """
  Generates the DID from secret key.

  Options:

    `:form`: Determines the form of DID returned. `:long` - The returned DID will be prefixed by "did:abt:". `:short` - The retuned DID has only DID string.

    `:encode`: Detemines whether or not encode the DID. `true` - The returned DID will be encoded as Base58. `false` - The returned DID will be in binary format and `:form` will be set as `:short`.

  ## Examples

      iex> sk = "3E0F9A313300226D51E33D5D98A126E86396956122E97E32D31CEE2277380B83FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{}, sk)
      "did:abt:z1ioGHFYiEemfLa3hQjk4JTwWTQPu1g2YxP"

      iex> sk = "3E0F9A313300226D51E33D5D98A126E86396956122E97E32D31CEE2277380B83FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> AbtDid.sk_to_did(AbtDid.Type.node, sk)
      "did:abt:z89nF4GRYvgw5mqk8NqVVC7NeZLWKbcbQY7V"

      iex> sk = "3E0F9A313300226D51E33D5D98A126E86396956122E97E32D31CEE2277380B83FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> AbtDid.sk_to_did(AbtDid.Type.validator, sk)
      "did:abt:zyt2vg6n8424c9xdXLGj1g27finM77ZN5KQL"

      iex> sk = "3E0F9A313300226D51E33D5D98A126E86396956122E97E32D31CEE2277380B83FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{role_type: :node}, sk)
      ** (RuntimeError) The hash_type must be :sha2 and key_type must be :ed25519 if the role_type is :node or :validator.

      iex> sk = "26954E19E8781905E2CF91A18AE4F36A954C142176EE1BC27C2635520C49BC55" |> Base.decode16!()
      iex> AbtDid.sk_to_did(%AbtDid.Type{role_type: :validator, key_type: :secp256k1}, sk)
      ** (RuntimeError) The hash_type must be :sha2 and key_type must be :ed25519 if the role_type is :node or :validator.

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

    `:form`: Determines the form of DID returned. `:long` - The returned DID will be prefixed by "did:abt:". `:short` - The retuned DID has only DID string.

    `:encode`: Detemines whether or not encode the DID. `true` - The returned DID will be encoded as Base58. `false` - The returned DID will be in binary format and `:form` will be set as `:short`.
  """
  @spec pk_to_did(DidType.t(), binary(), Keyword.t()) :: String.t()
  def pk_to_did(did_type, pk, opts \\ []) do
    hash = hash(did_type.hash_type, pk)
    pk_hash_to_did(did_type, hash, opts)
  end

  @doc """
  Alias to `pk_to_did`. See `pk_to_did` for more information.
  """
  @spec data_to_did(DidType.t(), binary(), Keyword.t()) :: String.t()
  def data_to_did(did_type, data, opts \\ []), do: pk_to_did(did_type, data, opts)

  @doc """
  Generate the DID from a public key hash.

  Options:

    `:form`: Determines the form of DID returned. `:long` - The returned DID will be prefixed by "did:abt:". `:short` - The retuned DID has only DID string.

    `:encode`: Detemines whether or not encode the DID. `true` - The returned DID will be encoded as Base58. `false` - The returned DID will be in binary format and `:form` will be set as `:short`.

  ## Examples

      iex> sk = "3E0F9A313300226D51E33D5D98A126E86396956122E97E32D31CEE2277380B83FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> did = AbtDid.sk_to_did(AbtDid.Type.validator, sk)
      iex> pk_hash = AbtDid.get_pubkey_hash(did)
      iex> AbtDid.pkhash_to_did(:validator, pk_hash)
      "did:abt:zyt2vg6n8424c9xdXLGj1g27finM77ZN5KQL"

      iex> pk = "FF47B3022FA503EAA1E9FA4B20FA8B16694EA56096F3A2E9109714062B3486D9" |> Base.decode16!()
      iex> AbtDid.pk_to_did(AbtDid.Type.node, pk)
      "did:abt:z89nF4GRYvgw5mqk8NqVVC7NeZLWKbcbQY7V"
      iex> pk_hash = "D1B287B1ACB71A980568C99A3AB32A8ED1D9C1BB" |> Base.decode16!()
      iex> AbtDid.pkhash_to_did(:node, pk_hash)
      "did:abt:z89nF4GRYvgw5mqk8NqVVC7NeZLWKbcbQY7V"
  """
  def pkhash_to_did(_, pk_hash, opts \\ [])

  @spec pkhash_to_did(:node, binary() | String.t(), Keyword.t()) :: String.t()
  def pkhash_to_did(:node, hash, opts) do
    %AbtDid.Type{role_type: :node, hash_type: :sha2, key_type: :ed25519}
    |> pk_hash_to_did(hash, opts)
  end

  @spec pkhash_to_did(:validator, binary() | String.t(), Keyword.t()) :: String.t()
  def pkhash_to_did(:validator, hash, opts) do
    %AbtDid.Type{role_type: :validator, hash_type: :sha2, key_type: :ed25519}
    |> pk_hash_to_did(hash, opts)
  end

  @spec pkhash_to_did(:tether, binary() | String.t(), Keyword.t()) :: String.t()
  def pkhash_to_did(:tether, hash, opts) do
    %AbtDid.Type{role_type: :tether, hash_type: :sha2, key_type: :ed25519}
    |> pk_hash_to_did(hash, opts)
  end

  @spec pkhash_to_did(:swap, binary() | String.t(), Keyword.t()) :: String.t()
  def pkhash_to_did(:swap, hash, opts) do
    %AbtDid.Type{role_type: :swap, hash_type: :sha2, key_type: :ed25519}
    |> pk_hash_to_did(hash, opts)
  end

  @spec pkhash_to_did(atom(), binary() | String.t(), Keyword.t()) :: String.t()
  def pkhash_to_did(role_type, hash, opts) do
    %AbtDid.Type{role_type: role_type, hash_type: :sha3, key_type: :ed25519}
    |> pk_hash_to_did(hash, opts)
  end

  @doc """
  Alias to `pkhash_to_did`. See `pkhash_to_did` for more information.
  """
  @spec hash_to_did(atom(), binary() | String.t(), Keyword.t()) :: String.t()
  def hash_to_did(type, hash, opts), do: pkhash_to_did(type, hash, opts)

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

  @doc """
  Gets the public key hash of this DID.

  ## Examples

      iex> pk = <<136, 159, 157, 15, 85, 1, 98, 93, 76, 139, 60, 21, 243, 144, 249, 180, 60, 69, 140, 215, 195, 6, 33, 122, 117, 140, 241, 209, 47, 83, 173, 77>>
      iex> did = AbtDid.pk_to_did(AbtDid.Type.validator, pk)
      iex> AbtDid.get_pubkey_hash(did)
      "BB6FD53B8B12E79CE94768B0349836AB9ED81D85"
  """
  @spec get_pubkey_hash(<<_::8, _::_*8>>, keyword()) :: binary()
  def get_pubkey_hash(did, opts \\ [encode: true])
  def get_pubkey_hash(@prefix <> did, opts), do: get_pubkey_hash(did, opts)

  def get_pubkey_hash(did, opts) do
    <<_::binary-size(2), pubkey_hash::binary-size(20), _::binary-size(4)>> =
      Multibase.decode!(did)

    case Keyword.get(opts, :encode, true) do
      true -> Base.encode16(pubkey_hash)
      _ -> pubkey_hash
    end
  end

  ############   private functiosn    ############

  # Options:
  # `:form`: Determines the form of DID returned. `:long` - The returned DID will be prefixed by "did:abt:". `:short` - The retuned DID has only DID string.
  # `:encode`: Detemines whether or not encode the DID. `true` - The returned DID will be encoded as Base58. `false` - The returned DID will be in binary format and `:form` will be set as `:short`.
  @spec pk_hash_to_did(DidType.t(), binary() | String.t(), Keyword.t()) :: String.t()
  defp pk_hash_to_did(did_type, hash, opts) do
    pk_hash_bin =
      case String.valid?(hash) do
        true ->
          case Base.decode16(hash, case: :mixed) do
            {:ok, v} -> v
            _ -> hash
          end

        _ ->
          hash
      end

    <<pk_hash::binary-size(20), _::binary>> = pk_hash_bin
    do_pk_hash_to_did(did_type, pk_hash, opts)
  end

  # Options:
  # `:form`: Determines the form of DID returned. `:long` - The returned DID will be prefixed by "did:abt:". `:short` - The retuned DID has only DID string.
  # `:encode`: Detemines whether or not encode the DID. `true` - The returned DID will be encoded as Base58. `false` - The returned DID will be in binary format and `:form` will be set as `:short`.
  @spec do_pk_hash_to_did(DidType.t(), binary(), Keyword.t()) :: String.t()
  defp do_pk_hash_to_did(%DidType{} = did_type, pk_hash, opts) do
    AbtDid.Type.check_did_type!(did_type)
    type_bytes = TypeBytes.struct_to_bytes(did_type)
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

  defp sk_to_pk(:ed25519, sk), do: Mcrypto.sk_to_pk(@ed25519, sk)
  defp sk_to_pk(:secp256k1, sk), do: Mcrypto.sk_to_pk(@secp256k1, sk)

  defp hash(:keccak, data), do: Mcrypto.hash(@keccak, data)
  defp hash(:sha3, data), do: Mcrypto.hash(@sha3, data)
  defp hash(:keccak_384, data), do: Mcrypto.hash(@keccak_384, data)
  defp hash(:sha3_384, data), do: Mcrypto.hash(@sha3_384, data)
  defp hash(:keccak_512, data), do: Mcrypto.hash(@keccak_512, data)
  defp hash(:sha3_512, data), do: Mcrypto.hash(@sha3_512, data)
  defp hash(:sha2, data), do: Mcrypto.hash(@sha2, data)
end
