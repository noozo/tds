defmodule MaxResponseBytesTest do
  use ExUnit.Case, async: true

  # A loopback TCP peer plays the server: it reads the SQL batch and answers
  # with the given TDS packets, one at a time when the test says so.

  # DONE with the count bit set and 5 rows
  @done <<0xFD, 0x10::little-16, 0xC1::little-16, 5::little-64>>

  defp packet(status, data) do
    <<0x04, status, byte_size(data) + 8::16, 0::16, 1, 0>> <> data
  end

  defp start_server(packets) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    test = self()

    server =
      spawn_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listen)
        {:ok, _batch} = :gen_tcp.recv(sock, 0)

        for packet <- packets do
          receive do: (:next -> :ok)
          _ = :gen_tcp.send(sock, packet)
        end

        send(test, {:server_done, :gen_tcp.recv(sock, 0, 1_000)})
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    {server, client}
  end

  defp execute(client, opts) do
    s = %Tds.Protocol{sock: {:gen_tcp, client}, opts: opts}
    Tds.Protocol.handle_execute(%Tds.Query{statement: "SELECT 1"}, [], [], s)
  end

  defp feed(server, count), do: for(_ <- 1..count, do: send(server, :next))

  test "a response under the limit decodes normally" do
    <<first::binary-5, rest::binary>> = @done
    {server, client} = start_server([packet(0, first), packet(1, rest)])
    feed(server, 2)

    assert {:ok, _query, %Tds.Result{num_rows: 5}, _s} =
             execute(client, max_response_bytes: 100)
  end

  test "without the option a large response is read in full" do
    junk = packet(0, <<0::size(4000)-unit(8)>>)
    {server, client} = start_server([junk, junk, packet(1, @done)])
    feed(server, 3)

    # the padding is not a valid token stream, so decoding fails once it
    # has all been buffered
    assert {:error, %RuntimeError{message: "Unsupported Token code" <> _}, _s} =
             execute(client, [])
  end

  test "a response over the limit stops reading and closes the connection" do
    junk = packet(0, <<0::size(4000)-unit(8)>>)
    {server, client} = start_server([junk, junk, junk, packet(1, @done)])
    # only two packets are ever sent before the error comes back
    feed(server, 2)

    # the second 4008 byte packet takes the count past the limit
    assert {:disconnect,
            %Tds.ResponseTooLargeError{
              limit: 6_000,
              received: 8_016,
              message: "response exceeded max_response_bytes (limit 6000 bytes)"
            }, _s} = execute(client, max_response_bytes: 6_000)

    assert {:error, _closed} = :inet.peername(client)

    # the server is still waiting to send the rest when the client hangs up
    feed(server, 2)
    assert_receive {:server_done, {:error, :closed}}
  end

  describe "through Tds.query/3" do
    # Just enough of a server to get through PRELOGIN (no encryption), LOGIN7
    # and the connection SET batch, then answer the query with `packets`
    defp start_sql_server(packets) do
      {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen)
      test = self()

      spawn_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listen)

        # PRELOGIN: VERSION and ENCRYPTION (ENCRYPT_NOT_SUP)
        recv_message(sock)
        prelogin = <<0x00, 11::16, 6::16, 0x01, 17::16, 1::16, 0xFF, 16, 0, 0, 0, 0, 0, 0x02>>
        :ok = :gen_tcp.send(sock, packet(1, prelogin))

        # LOGIN7: LOGINACK and DONE
        recv_message(sock)
        ack = <<1, 0x74000004::32, 1, ?M, 0, 16, 0, 0, 0>>
        :ok = :gen_tcp.send(sock, packet(1, <<0xAD, byte_size(ack)::little-16>> <> ack <> @done))

        # connection SET statements
        recv_message(sock)
        :ok = :gen_tcp.send(sock, packet(1, @done))

        recv_message(sock)
        for packet <- packets, do: _ = :gen_tcp.send(sock, packet)
        send(test, {:server_done, :gen_tcp.recv(sock, 0, 1_000)})
      end)

      {:ok, pid} =
        Tds.start_link(
          hostname: "127.0.0.1",
          port: port,
          username: "u",
          password: "p",
          ssl: false,
          execution_mode: :executesql,
          max_response_bytes: 6_000,
          backoff_type: :stop,
          pool_size: 1
        )

      pid
    end

    # Reads one client message, packet by packet, up to the EOM status bit
    defp recv_message(sock) do
      {:ok, <<_type, status, length::16, _::binary-4>>} = :gen_tcp.recv(sock, 8)
      {:ok, _data} = :gen_tcp.recv(sock, length - 8)
      if status == 0, do: recv_message(sock), else: :ok
    end

    @tag :capture_log
    test "a response under the limit returns the result" do
      pid = start_sql_server([packet(1, @done)])

      assert {:ok, %Tds.Result{num_rows: 5}} = Tds.query(pid, "SELECT 1", [])
    end

    @tag :capture_log
    test "a response over the limit returns ResponseTooLargeError and closes the connection" do
      junk = packet(0, <<0::size(4000)-unit(8)>>)
      pid = start_sql_server([junk, junk, junk, packet(1, @done)])

      assert {:error,
              %Tds.ResponseTooLargeError{
                limit: 6_000,
                received: received,
                message: "response exceeded max_response_bytes (limit 6000 bytes)"
              }} = Tds.query(pid, "SELECT 1", [])

      assert received > 6_000
      assert_receive {:server_done, {:error, :closed}}
    end
  end
end
