defmodule AbtDid.MixProject do
  use Mix.Project

  @top File.cwd!()

  @version @top |> Path.join("version") |> File.read!() |> String.trim()
  @elixir_version @top |> Path.join(".elixir_version") |> File.read!() |> String.trim()
  @otp_version @top |> Path.join(".otp_version") |> File.read!() |> String.trim()

  def get_version, do: @version
  def get_elixir_version, do: @elixir_version
  def get_otp_version, do: @otp_version

  def project do
    [
      app: :abt_did_elixir,
      version: @version,
      elixir: @elixir_version,
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      deps: deps(),
      description: description(),
      package: package(),
      # Docs
      name: "AbtDid",
      source_url: "https://github.com/arcblock/abt-did-elixir",
      homepage_url: "https://github.com/arcblock/abt-did-elixir",
      docs: [
        main: "AbtDid",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(:integration), do: elixirc_paths(:test)
  defp elixirc_paths(:dev), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:multibase, "~> 0.0.1"},
      {:typed_struct, "~> 0.1.4"},
      {:jason, "~> 1.1"},

      # mcrypto
      {:mcrypto, "~> 0.2"},

      # deployment
      {:distillery, "~> 2.0", runtime: false},

      # dev & test
      {:excoveralls, "~> 0.10", only: [:test, :integration]},
      {:ex_doc, "~> 0.19.0", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    """
    Elixir implementation of [ABT DID protocol](https://github.com/ArcBlock/abt-did-spec).
    """
  end

  defp package do
    [
      files: [
        "config",
        "lib",
        "mix.exs",
        "README*",
        "version",
        ".elixir_version",
        ".otp_version"
      ],
      licenses: ["Apache 2.0"],
      maintainers: [
        "christinaleizhou@gmail.com",
        "dingpl716@gmail.com",
        "sunboshan@gmail.com",
        "tyr.chen@gmail.com"
      ],
      links: %{
        "GitHub" => "https://github.com/arcblock/abt-did-elixir",
        "Docs" => "https://hexdocs.pm/abt-did-elixir"
      }
    ]
  end
end
