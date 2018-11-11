# Azure Active Directory OpenID

[![Build Status][travis-img]][travis] [![Hex Version][hex-img]][hex] [![License][license-img]][license]

[travis-img]: https://travis-ci.org/whossname/azure_ad_openid.svg?branch=master
[travis]: https://travis-ci.org/whossname/azure_ad_openid
[hex-img]: https://img.shields.io/hexpm/v/azure_ad_openid.svg
[hex]: https://hex.pm/packages/azure_ad_openid
[license-img]: http://img.shields.io/badge/license-MIT-brightgreen.svg
[license]: http://opensource.org/licenses/MIT


Azure Active Directory authentication using OpenID.

This is a simple and opinionated OpenID authentication library for Azure Active Directory.
The following decisions have been made:

- The authorization response mode is "form_post"
- The authorization response type is "code id_token"
- The nonce has a timeout of 15 minutes
- The callback will reject id_tokens with an iat that is more than 6 minutes old
- The client secret is not used, so this library can't be used for authorization

The callback function includes client side validations (found in `AzureADOpenId.VerifyClaims`)
for the following id_token fields:
- c_hash
- aud
- tid
- iss
- nbf
- iat
- exp
- nonce

Nonces are stored using an `Agent` called `AzureADOpenId.NonceStore`.

## Installation

The package can be installed by adding `azure_ad_openid` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:azure_ad_openid, "~> 0.1"},
  ]
end
```

## Basic Usage

In order to use this library you will need to first start the `AzureADOpenId.NonceStore`.
It is a good idea to add it as a child to a supervisor. For example in a Phoenix app:

```elixir
def start(_type, _args) do
  children = [
    AzureADOpenId.NonceStore,
    MyAppWeb.Endpoint,
  ]
  opts = [strategy: :one_for_one, name: MyApp.Supervisor]
  Supervisor.start_link(children, opts)
end
```

This library can be used with or without the standard Elixir configuration. If you want to
use it with configuration set the following in your config files:

```elixir
config :azure_ad_openid, AzureADOpenId,
  client_id: <your client_id>,
  tenant: <your tenant>
```

If you don't setup the config, you will need to pass these values in manually at runtime.
For example to get the authorization url:

```elixir
config = [tenant: <your tenant>, client_id: <your client_id>]
AzureADOpenId.authorize_url!(<redirect_uri>, config)
```

The following is a simple example of a Phoenix authentication controller that uses this library:

```elixir
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller

  alias AzureADOpenId

  def login(conn, _) do
    base_uri = Application.get_env(:my_app, :base_uri)
    redirect_uri = "#{base_uri}/auth/callback"
    redirect conn, external: AzureADOpenId.authorize_url!(redirect_uri)
  end

  def callback(conn, _) do
    {:ok, claims} = AzureADOpenId.handle_callback!(conn)

    conn
    |> put_session(:user_claims, claims)
    |> redirect(to: "/")
  end

  def logout(conn, _) do
    conn
    |> put_session(:user_claims, nil)
    |> redirect(external: AzureADOpenId.logout_url())
  end
end
```

## Documentation

The docs can be found at
[https://hexdocs.pm/azure_ad_openid ](https://hexdocs.pm/azure_ad_openid/readme.html).

## Credit

The following repository was used as a base for the AzureAD authentication:

[https://github.com/onurkucukkece/oauth_azure_activedirectory ](https://github.com/onurkucukkece/oauth_azure_activedirectory)

## License

Please see [LICENSE](https://github.com/whossname/azure_ad_openid/blob/master/LICENSE.md)
for licensing details.

