defmodule FedAuthTest do
  use ExUnit.Case, async: true

  import Tds.Messages, only: [msg_error: 1, msg_loginack: 1]

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

    test "the login parser records the acknowledged features" do
      ack = <<0xAE, 0x02, 0::little-32, 0xFF>>

      assert {msg_loginack(features: [0x02]), %Tds.Protocol{}} =
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
      token = fn -> flunk("resolved") end
      without_ssl = [access_token: token] ++ Keyword.delete(@opts, :ssl)

      for opts <- [
            without_ssl | for(ssl <- [false, :not_supported, nil], do: [ssl: ssl] ++ without_ssl)
          ] do
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

    test "returns an error naming only the exception when the token function raises" do
      opts = [access_token: fn -> raise "SECRET-BOOM" end] ++ @opts

      assert {:error, %Tds.Error{message: message}} = Tds.Protocol.connect(opts)
      assert message == "access token could not be fetched: RuntimeError"
    end

    test "returns an error when the token function throws or exits" do
      for fun <- [fn -> throw(:boom) end, fn -> exit(:boom) end] do
        assert {:error, %Tds.Error{message: "access token could not be fetched: " <> kind}} =
                 Tds.Protocol.connect([access_token: fun] ++ @opts)

        assert kind in ["throw", "exit"]
      end
    end

    test "gives up on a token function slower than connect_timeout" do
      opts = [access_token: fn -> Process.sleep(5_000) end, connect_timeout: 50] ++ @opts

      assert {:error, %Tds.Error{message: message}} = Tds.Protocol.connect(opts)
      assert message == "access token could not be fetched: timed out after 50ms"
    end

    @tag :capture_log
    test "a raising token function leaves the pool alive and backs off" do
      parent = self()

      token = fn ->
        send(parent, :token_called)
        raise "SECRET-BOOM"
      end

      {:ok, pool} =
        Tds.start_link(
          [access_token: token, pool_size: 1, backoff_min: 10, backoff_max: 20] ++ @opts
        )

      for _ <- 1..3, do: assert_receive(:token_called, 1_000)
      assert Process.alive?(pool)

      assert {:error, %DBConnection.ConnectionError{}} =
               Tds.query(pool, "SELECT 1", [], queue_target: 10, queue_interval: 10, timeout: 50)
    end
  end
end
