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

    assert {:disconnect, %Tds.Error{message: "response exceeded max_response_bytes (6000)"},
            _s} = execute(client, max_response_bytes: 6_000)

    assert {:error, _closed} = :inet.peername(client)

    # the server is still waiting to send the rest when the client hangs up
    feed(server, 2)
    assert_receive {:server_done, {:error, :closed}}
  end
end
