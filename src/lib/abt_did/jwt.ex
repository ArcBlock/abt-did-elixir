defmodule AbtDid.Jwt do
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

  @doc """
  Generates and signs the challenge.
  """
  @spec gen_and_sign(Type.t(), binary(), map()) :: String.t()
  def gen_and_sign(did_type, sk, extra \\ %{}) do
    did = AbtDid.sk_to_did(did_type, sk)
    now = DateTime.utc_now() |> DateTime.to_unix()

    data =
      %{
        "iss" => did,
        "iat" => "#{inspect(now)}",
        "nbf" => "#{inspect(now)}",
        "exp" => "#{inspect(now + @min_30)}"
      }
      |> Map.merge(extra)
      |> Jason.encode!()
      |> Base.url_encode64(padding: false)
      |> gen(did_type.key_type)

    sig = sign(did_type.key_type, data, sk)
    data <> "." <> sig
  end

  @doc """
  Verifies if the `challenge` is signed by the secret key of the `pk` and also
  verifies if the DID contained in the iss field of the `challenge` matches the `pk`.
  """
  @spec verify(String.t(), binary()) :: boolean
  def verify(challenge, pk) do
    [header, body, signature] = String.split(challenge, ".")

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
  end

  defp get_signer(%{"alg" => "ES256K", "typ" => "JWT"}), do: @secp256k1
  defp get_signer(%{"alg" => "Ed25519", "typ" => "JWT"}), do: @ed25519

  defp sign(:secp256k1, data, sk),
    do: Mcrypto.sign!(@secp256k1, data, sk) |> Base.url_encode64(padding: false)

  defp sign(:ed25519, data, sk),
    do: Mcrypto.sign!(@ed25519, data, sk) |> Base.url_encode64(padding: false)

  defp gen(body, :secp256k1), do: @header_secp256k1 <> "." <> body
  defp gen(body, :ed25519), do: @header_ed25519 <> "." <> body
end
