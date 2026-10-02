Code.require_file("support/fake_tds_server.exs", __DIR__)

defmodule ConnectionFailureTest do
  # changes the global log level
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Tds.FakeServer

  setup do
    level = Logger.level()
    Logger.configure(level: :debug)
    on_exit(fn -> Logger.configure(level: level) end)
  end

  defp start_conn(port, opts \\ []) do
    Tds.start_link(
      [
        hostname: "127.0.0.1",
        port: port,
        username: "u",
        password: "p",
        ssl: false,
        execution_mode: :executesql,
        backoff_type: :stop,
        pool_size: 1
      ] ++ opts
    )
  end

  test "a socket closed mid-response returns a disconnect error" do
    partial = FakeServer.packet(0, <<0::size(100)-unit(8)>>)
    {_server, port} = FakeServer.start(script: [{:close, [partial]}])
    {:ok, pid} = start_conn(port)

    log =
      capture_log(fn ->
        assert {:error, %Tds.Error{message: "Connection failed to receive packet due :closed"}} =
                 Tds.query(pid, "SELECT 1", [])

        # the pool drops the broken connection
        Process.sleep(100)
      end)

    refute log =~ "bad return value"
  end

  test "a server that stops answering times out" do
    {_server, port} = FakeServer.start(script: [:hang])
    {:ok, pid} = start_conn(port)

    log =
      capture_log(fn ->
        assert {:error, error} = Tds.query(pid, "SELECT 1", [], timeout: 200)
        assert %Tds.Error{message: "Connection failed to receive packet due :closed"} = error
        Process.sleep(100)
      end)

    assert log =~ "timed out"
    refute log =~ "bad return value"
  end
end
