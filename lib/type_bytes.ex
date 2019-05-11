defmodule AbtDid.Type do
  @moduledoc """
  Represents the type of the DID. A DID is composed of three inner types: `role_type`, `key_type` and `hash_type`.
  """

  use TypedStruct

  typedstruct do
    field(:role_type, atom(), default: :account)
    field(:key_type, atom(), default: :ed25519)
    field(:hash_type, atom(), default: :sha3)
  end

  @doc """
  Returns the DID type representing a blockchain node.
  """
  @spec node() :: AbtDid.Type.t()
  def node, do: %AbtDid.Type{role_type: :node, key_type: :ed25519, hash_type: :sha2}

  @doc """
  Returns the DID type representing a blockchain validator.
  """
  @spec validator() :: AbtDid.Type.t()
  def validator, do: %AbtDid.Type{role_type: :validator, key_type: :ed25519, hash_type: :sha2}

  @doc """
  Returns the DID type representing a tether.
  """
  @spec tether() :: AbtDid.Type.t()
  def tether, do: %AbtDid.Type{role_type: :tether, key_type: :ed25519, hash_type: :sha2}

  @doc """
  Checks if a Did type is valid or not.
  """
  @spec check_did_type!(AbtDid.Type.t()) :: :ok
  def check_did_type!(%{role_type: role, hash_type: hash, key_type: key})
      when role in [:validator, :node, :tether] do
    if hash == :sha2 and key == :ed25519 do
      :ok
    else
      raise "The hash_type must be :sha2 and key_type must be :ed25519 if the role_type is :node or :validator."
    end
  end

  def check_did_type!(%{role_type: _, hash_type: hash, key_type: _}) do
    if hash == :sha2 do
      raise "The hash_type :sha2 is only used for role_type :node, :validator or :tether."
    else
      :ok
    end
  end
end

defmodule AbtDid.TypeBytes do
  @moduledoc """
  Encodes the DId type information into bytes.
  """

  alias AbtDid.Type

  @doc """
  Converts the DID type struct to type bytes.

  ## Examples

      iex> AbtDid.TypeBytes.struct_to_bytes(%AbtDid.Type{})
      <<0, 1>>

      iex> AbtDid.TypeBytes.struct_to_bytes(%AbtDid.Type{hash_type: :sha3_512})
      <<0, 5>>

      iex> AbtDid.TypeBytes.struct_to_bytes(%AbtDid.Type{role_type: :application, key_type: :secp256k1, hash_type: :sha3_512})
      "\f%"

      iex> AbtDid.TypeBytes.struct_to_bytes(%AbtDid.Type{role_type: :application, hash_type: :sha2})
      ** (RuntimeError) The hash_type :sha2 is only used for role_type :node, :validator or :tether.
  """
  @spec struct_to_bytes(Type.t()) :: binary()
  def struct_to_bytes(type) do
    AbtDid.Type.check_did_type!(type)
    <<_::bitstring-size(2), role::bitstring-size(6)>> = role_type_to_bytes(type.role_type)
    <<_::bitstring-size(3), key::bitstring-size(5)>> = key_type_to_bytes(type.key_type)
    <<_::bitstring-size(3), hash::bitstring-size(5)>> = hash_type_to_bytes(type.hash_type)

    <<role::bitstring, key::bitstring, hash::bitstring>>
  end

  @doc """
  Converts the DID type bytes to DID type struct.

  ## Examples

      iex> AbtDid.TypeBytes.bytes_to_struct(<<0, 1>>)
      %AbtDid.Type{hash_type: :sha3, key_type: :ed25519, role_type: :account}

      iex> AbtDid.TypeBytes.bytes_to_struct(<<0, 5>>)
      %AbtDid.Type{hash_type: :sha3_512, key_type: :ed25519, role_type: :account}

      iex> AbtDid.TypeBytes.bytes_to_struct("\f%")
      %AbtDid.Type{role_type: :application, key_type: :secp256k1, hash_type: :sha3_512}

      iex> AbtDid.TypeBytes.bytes_to_struct(<<196, 5>>)
      ** (RuntimeError) Invliad role type: \"1\"
  """
  @spec bytes_to_struct(binary()) :: Type.t()
  def bytes_to_struct(bytes) do
    <<role::bitstring-size(6), key::bitstring-size(5), hash::bitstring-size(5)>> = bytes
    role_type = bytes_to_role_type(<<0::size(2), role::bitstring>>)
    key_type = bytes_to_key_type(<<0::size(3), key::bitstring>>)
    hash_type = bytes_to_hash_type(<<0::size(3), hash::bitstring>>)

    %Type{role_type: role_type, key_type: key_type, hash_type: hash_type}
  end

  defp role_type_to_bytes(:account), do: <<0>>
  defp role_type_to_bytes(:node), do: <<1>>
  defp role_type_to_bytes(:device), do: <<2>>
  defp role_type_to_bytes(:application), do: <<3>>
  defp role_type_to_bytes(:smart_contract), do: <<4>>
  defp role_type_to_bytes(:bot), do: <<5>>
  defp role_type_to_bytes(:asset), do: <<6>>
  defp role_type_to_bytes(:stake), do: <<7>>
  defp role_type_to_bytes(:validator), do: <<8>>
  defp role_type_to_bytes(:group), do: <<9>>
  defp role_type_to_bytes(:tx), do: <<10>>
  defp role_type_to_bytes(:tether), do: <<11>>
  defp role_type_to_bytes(:any), do: <<63>>
  defp role_type_to_bytes(role), do: raise("Invliad role type: #{inspect(role)}")

  defp bytes_to_role_type(<<0>>), do: :account
  defp bytes_to_role_type(<<1>>), do: :node
  defp bytes_to_role_type(<<2>>), do: :device
  defp bytes_to_role_type(<<3>>), do: :application
  defp bytes_to_role_type(<<4>>), do: :smart_contract
  defp bytes_to_role_type(<<5>>), do: :bot
  defp bytes_to_role_type(<<6>>), do: :asset
  defp bytes_to_role_type(<<7>>), do: :stake
  defp bytes_to_role_type(<<8>>), do: :validator
  defp bytes_to_role_type(<<9>>), do: :group
  defp bytes_to_role_type(<<10>>), do: :tx
  defp bytes_to_role_type(<<11>>), do: :tether
  defp bytes_to_role_type(<<63>>), do: :any
  defp bytes_to_role_type(role), do: raise("Invliad role type: #{inspect(role)}")

  defp key_type_to_bytes(:ed25519), do: <<0>>
  defp key_type_to_bytes(:secp256k1), do: <<1>>
  defp key_type_to_bytes(key), do: raise("Invliad key type: #{inspect(key)}")

  defp bytes_to_key_type(<<0>>), do: :ed25519
  defp bytes_to_key_type(<<1>>), do: :secp256k1
  defp bytes_to_key_type(key), do: raise("Invliad key type: #{inspect(key)}")

  defp hash_type_to_bytes(:keccak), do: <<0>>
  defp hash_type_to_bytes(:sha3), do: <<1>>
  defp hash_type_to_bytes(:keccak_384), do: <<2>>
  defp hash_type_to_bytes(:sha3_384), do: <<3>>
  defp hash_type_to_bytes(:keccak_512), do: <<4>>
  defp hash_type_to_bytes(:sha3_512), do: <<5>>
  defp hash_type_to_bytes(:sha2), do: <<6>>
  defp hash_type_to_bytes(hash), do: raise("Invliad hash type: #{inspect(hash)}")

  defp bytes_to_hash_type(<<0>>), do: :keccak
  defp bytes_to_hash_type(<<1>>), do: :sha3
  defp bytes_to_hash_type(<<2>>), do: :keccak_384
  defp bytes_to_hash_type(<<3>>), do: :sha3_384
  defp bytes_to_hash_type(<<4>>), do: :keccak_512
  defp bytes_to_hash_type(<<5>>), do: :sha3_512
  defp bytes_to_hash_type(<<6>>), do: :sha2
  defp bytes_to_hash_type(hash), do: raise("Invliad hash type: #{inspect(hash)}")
end
