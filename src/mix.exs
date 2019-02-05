defmodule AbtDid.MixProject do
  use Mix.Project

  @version File.cwd!() |> Path.join("../version") |> File.read!() |> String.trim()
  @elixir_version File.cwd!() |> Path.join(".elixir_version") |> File.read!() |> String.trim()
  @otp_version File.cwd!() |> Path.join(".otp_version") |> File.read!() |> String.trim()

  def get_version, do: @version
  def get_elixir_version, do: @elixir_version
  def get_otp_version, do: @otp_version

  def project do
    [
      app: :,
      version: @version,
      elixir: @elixir_version,
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: { AbtDid.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},

      # utility tools for error logs and metrics
      {:ex_datadog_plug, "~> 0.5.0"},
      {:logger_sentry, "~> 0.2"},
      {:recon, "~> 2.3"},
      {:recon_ex, "~> 0.9.1"},
      {:sentry, "~> 7.0"},
      {:statix, "~> 1.1"},

      # deployment
      {:distillery, "~> 1.5", override: true},

      # dev & test
      {:credo, "~> 1.0", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 0.5", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: [:dev, :test], runtime: false},
      {:excheck, "~> 0.6", only: :test, runtime: false},
      {:pre_commit_hook, "~> 1.2", only: [:dev, :test], runtime: false},
      {:triq, "~> 1.3", only: :test, runtime: false},

      # test only
      {:ex_machina, "~> 2.2", only: [:dev, :test]},
      {:faker, "~> 0.11", only: [:dev, :test]},
      {:mock, "~> 0.3", only: [:dev, :test]},
      {:excoveralls, "~> 0.10", only: [:dev, :test]}
    ]
  end
end
