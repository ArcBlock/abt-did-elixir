defmodule AbtDid.Signer do
  alias AbtDid
  alias AbtDid.Type

  @secp256k1 %Mcrypto.Signer.Secp256k1{}
  @ed25519 %Mcrypto.Signer.Ed25519{}

  @header_secp256k1 %{"alg" => "ES256K", "typ" => "JWT"}
                    |> Jason.encode!()
                    |> Base.url_encode64(padding: false)
  @header_ed25519 %{"alg" => "Ed25519", "typ" => "JWT"}
                  |> Jason.encode!()
                  |> Base.url_encode64(padding: false)
  @min_30 60 * 30
  @prefix "did:abt:"

  @doc """
  Generates and signs the token.
  """
  @spec gen_and_sign(Type.t() | String.t(), binary(), map()) :: String.t()
  def gen_and_sign(_, _, extra \\ %{})

  def gen_and_sign(%Type{} = did_type, sk, extra) do
    did = AbtDid.sk_to_did(did_type, sk)
    do_gen_and_sign(did_type, did, sk, extra)
  end

  def gen_and_sign(did, sk, extra) do
    did_type = AbtDid.get_did_type(did)
    do_gen_and_sign(did_type, did, sk, extra)
  end

  @doc """
  Verifies if the `token` is signed by the secret key of the `pk` and also
  verifies if the DID contained in the iss field of the `token` matches the `pk`.
  """
  @spec verify(String.t(), binary()) :: boolean
  def verify(token, pk) do
    [header, body, signature] = String.split(token, ".")

    signer =
      header
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()
      |> get_signer()

    did =
      body
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()
      |> Map.get("iss")

    signature = Base.url_decode64!(signature, padding: false)
    Mcrypto.verify(signer, header <> "." <> body, signature, pk) && AbtDid.match_pk?(did, pk)
  rescue
    _ -> false
  end

  defp do_gen_and_sign(did_type, did, sk, extra) do
    full_did =
      case did do
        @prefix <> _ -> did
        _ -> @prefix <> did
      end

    now = DateTime.utc_now() |> DateTime.to_unix()

    data =
      %{
        "iss" => full_did,
        "iat" => "#{inspect(now)}",
        "nbf" => "#{inspect(now)}",
        "exp" => "#{inspect(now + @min_30)}"
      }
      |> Map.merge(extra)
      |> clean_data()
      |> Jason.encode!()
      |> Base.url_encode64(padding: false)
      |> gen(did_type.key_type)

    sig = sign(did_type.key_type, data, sk)
    data <> "." <> sig
  end

  defp get_signer(%{"alg" => alg}) do
    case String.downcase(alg) do
      "secp256k1" -> @secp256k1
      "es256k" -> @secp256k1
      "ed25519" -> @ed25519
    end
  end

  defp sign(:secp256k1, data, sk),
    do: Mcrypto.sign!(@secp256k1, data, sk) |> Base.url_encode64(padding: false)

  defp sign(:ed25519, data, sk),
    do: Mcrypto.sign!(@ed25519, data, sk) |> Base.url_encode64(padding: false)

  defp gen(body, :secp256k1), do: @header_secp256k1 <> "." <> body
  defp gen(body, :ed25519), do: @header_ed25519 <> "." <> body

  defp clean_data(data) do
    data
    |> Map.to_list()
    |> Enum.reject(fn {_, value} -> is_nil(value) or "" === value end)
    |> Enum.into(%{})
  end
end
