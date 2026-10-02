defmodule FedAuthTest do
  use ExUnit.Case, async: true

  import Tds.Messages, only: [msg_error: 1, msg_loginack: 0]

  alias Tds.Protocol.Prelogin

  # PRELOGIN response: VERSION, ENCRYPTION (ENCRYPT_ON) and optionally
  # FEDAUTHREQUIRED, followed by the terminator and the option data
  defp prelogin_response(fed_auth_required) do
    fed_auth = if fed_auth_required, do: [{0x06, <<fed_auth_required>>}], else: []
    options = [{0x00, <<15, 0, 0x07, 0xD0, 0, 0>>}, {0x01, <<0x01>>} | fed_auth]
    offset = 5 * length(options) + 1

    {headers, data, _} =
      Enum.reduce(options, {<<>>, <<>>, offset}, fn {token, value}, {headers, data, offset} ->
        size = byte_size(value)
        {headers <> <<token, offset::16, size::16>>, data <> value, offset + size}
      end)

    headers <> <<0xFF>> <> data
  end

  describe "PRELOGIN" do
    test "always requests FEDAUTHREQUIRED, with or without an access token" do
      encode = fn opts ->
        opts |> Prelogin.encode() |> IO.iodata_to_binary()
      end

      assert encode.(ssl: true) == encode.(ssl: true, access_token: "tok")

      <<_header::binary-8, options::binary>> = encode.(ssl: true)
      # VERSION, ENCRYPTION, THREADID, MARS, FEDAUTHREQUIRED
      <<_::binary-20, 0x06, offset::16, 1::16, 0xFF, _::binary>> = options
      assert binary_part(options, offset, 1) == <<0x01>>
    end

    test "records the server FEDAUTHREQUIRED response as the echo flag" do
      s = %Tds.Protocol{opts: [ssl: true]}

      assert {:encrypt, %{fed_auth_echo: true}} = Prelogin.decode(prelogin_response(1), s)
      assert {:encrypt, %{fed_auth_echo: false}} = Prelogin.decode(prelogin_response(0), s)
      assert {:encrypt, %{fed_auth_echo: false}} = Prelogin.decode(prelogin_response(nil), s)
    end
  end

  describe "login response tokens" do
    # DONE token, final, no row count
    @done <<0xFD, 0::16, 0::16, 0::64>>

    test "FEATUREEXTACK is decoded and the token stream continues after it" do
      ack = <<0xAE, 0x02, 0::little-32, 0x0A, 1::little-32, 0x01, 0xFF>>

      assert [{:featureextack, [{0x02, ""}, {0x0A, <<0x01>>}]}, {:done, _}] =
               Tds.Tokens.decode_tokens(ack <> @done)
    end

    test "FEATUREEXTACK is ignored by the login parser" do
      ack = <<0xAE, 0x02, 0::little-32, 0xFF>>

      assert {msg_loginack(), %Tds.Protocol{}} =
               Tds.Messages.parse(:login, ack <> @done, %Tds.Protocol{})
    end

    test "FEDAUTHINFO fails the login with a clear error" do
      info = <<0xEE, 4::little-32, 1, 2, 3, 4>>

      assert {msg_error(error: %{msg_text: "Server requested FEDAUTHINFO" <> _}), _} =
               Tds.Messages.parse(:login, info <> @done, %Tds.Protocol{})
    end
  end

  describe "connect/1 with :access_token" do
    # Nothing listens on port 1, so a resolved token ends in a TCP error
    @opts [hostname: "127.0.0.1", port: 1, ssl: true, timeout: 1_000]

    test "refuses to send the token without encryption" do
      for ssl <- [false, :not_supported] do
        opts = Keyword.merge(@opts, ssl: ssl, access_token: fn -> flunk("resolved") end)

        assert {:error, %Tds.Error{message: ":access_token requires ssl" <> _}} =
                 Tds.Protocol.connect(opts)
      end
    end

    test "resolves a function on every connect" do
      parent = self()
      token = fn -> send(parent, :token_resolved) && {:ok, "tok"} end

      assert {:error, %Tds.Error{message: "tcp connect: " <> _}} =
               Tds.Protocol.connect([access_token: token] ++ @opts)

      assert_received :token_resolved
    end

    test "resolves an MFA" do
      opts = [access_token: {Function, :identity, ["tok"]}] ++ @opts

      assert {:error, %Tds.Error{message: "tcp connect: " <> _}} = Tds.Protocol.connect(opts)
    end

    test "returns an error when the token cannot be fetched" do
      opts = [access_token: fn -> {:error, :expired} end] ++ @opts

      assert {:error, %Tds.Error{message: "unable to fetch access token: :expired"}} =
               Tds.Protocol.connect(opts)

      assert {:error, %Tds.Error{message: "invalid :access_token" <> _}} =
               Tds.Protocol.connect([access_token: ""] ++ @opts)
    end
  end
end
