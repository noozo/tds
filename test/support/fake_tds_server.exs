defmodule Tds.FakeServer do
  @moduledoc false
  # Just enough of a SQL Server to get a client through PRELOGIN (optionally
  # with TLS, wrapped in PRELOGIN packets like the real thing), LOGIN7 and
  # the connection SET batch, then hand each query to a script.
  #
  # `script` is a list of steps run for each client query, in order:
  #   {:reply, packets} | {:close, packets} | :hang
  # and `login: :close` hangs up after reading LOGIN7.

  # DONE with the count bit set and 5 rows
  def done, do: <<0xFD, 0x10::little-16, 0xC1::little-16, 5::little-64>>

  def packet(status, data) do
    <<0x04, status, byte_size(data) + 8::16, 0::16, 1, 0>> <> data
  end

  def start(opts) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    test = self()
    server = spawn_link(fn -> serve(listen, test, opts) end)
    {server, port}
  end

  defp serve(listen, test, opts) do
    {:ok, sock} = :gen_tcp.accept(listen)
    tls? = Keyword.get(opts, :tls, false)

    # PRELOGIN: VERSION and ENCRYPTION (ON with TLS, NOT_SUP without)
    _ = recv_message({:gen_tcp, sock})
    encryption = if tls?, do: 0x01, else: 0x02
    prelogin = <<0x00, 11::16, 6::16, 0x01, 17::16, 1::16, 0xFF, 16, 0, 0, 0, 0, 0, encryption>>
    :ok = :gen_tcp.send(sock, packet(1, prelogin))

    conn = if tls?, do: {:ssl, tls_handshake(sock)}, else: {:gen_tcp, sock}

    login7 = recv_message(conn)
    send(test, {:login7, login7})

    case Keyword.get(opts, :login, :ok) do
      :close ->
        close(conn)

      :ok ->
        # LOGINACK, FEATUREEXTACK (FEDAUTH, no data) and DONE
        ack = <<1, 0x74000004::32, 1, ?M, 0, 16, 0, 0, 0>>
        loginack = <<0xAD, byte_size(ack)::little-16>> <> ack
        featureextack = <<0xAE, 0x02, 0::little-32, 0xFF>>
        send_data(conn, packet(1, loginack <> featureextack <> done()))

        # connection SET statements
        _ = recv_message(conn)
        send_data(conn, packet(1, done()))

        run(conn, Keyword.get(opts, :script, []), test)
    end
  end

  defp run(conn, [], test), do: send(test, {:server_done, recv(conn, 0, 1_000)})

  defp run(conn, [step | script], test) do
    _ = recv_message(conn)

    case step do
      {:reply, packets} ->
        Enum.each(packets, &send_data(conn, &1))
        run(conn, script, test)

      {:close, packets} ->
        Enum.each(packets, &send_data(conn, &1))
        close(conn)

      :hang ->
        send(test, {:server_done, recv(conn, 0, 5_000)})
    end
  end

  # The client's Tds.Tls transport wraps the handshake in PRELOGIN packets;
  # it is symmetric, so the server side can use it as well
  defp tls_handshake(sock) do
    %{server_config: server_config} =
      :public_key.pkix_test_data(%{
        server_chain: %{root: [], intermediates: [], peer: []},
        client_chain: %{root: [], intermediates: [], peer: []}
      })

    {:ok, tls} = GenServer.start_link(Tds.Tls, {sock, []})
    :ok = :gen_tcp.controlling_process(sock, tls)

    ssl_opts =
      server_config ++
        [
          versions: [:"tlsv1.2"],
          active: false,
          cb_info: {Tds.Tls, :tcp, :tcp_closed, :tcp_error}
        ]

    {:ok, ssl} = :ssl.handshake(sock, ssl_opts, 5_000)
    GenServer.cast(tls, :handshake_complete)
    ssl
  end

  # Reads one client message, packet by packet, up to the EOM status bit
  def recv_message(conn, acc \\ <<>>) do
    {:ok, <<_type, status, length::16, _::binary-4>>} = recv(conn, 8, 5_000)
    {:ok, data} = recv(conn, length - 8, 5_000)
    if status == 0, do: recv_message(conn, acc <> data), else: acc <> data
  end

  defp recv({:gen_tcp, sock}, n, timeout), do: :gen_tcp.recv(sock, n, timeout)
  defp recv({:ssl, sock}, n, timeout), do: :ssl.recv(sock, n, timeout)

  defp send_data({:gen_tcp, sock}, data), do: _ = :gen_tcp.send(sock, data)
  defp send_data({:ssl, sock}, data), do: _ = :ssl.send(sock, data)

  defp close({:gen_tcp, sock}), do: :gen_tcp.close(sock)
  defp close({:ssl, sock}), do: :ssl.close(sock)
end
