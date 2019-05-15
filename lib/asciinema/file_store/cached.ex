defmodule Asciinema.FileStore.Cached do
  use Asciinema.FileStore

  def url(path) do
    remote_store().url(path)
  end

  def put_file(dst_path, src_local_path, content_type, compress \\ false) do
    with :ok <- remote_store().put_file(dst_path, src_local_path, content_type, compress),
         :ok <- cache_store().put_file(dst_path, src_local_path, content_type, compress) do
      :ok
    end
  end

  def serve_file(conn, path, filename) do
    remote_store().serve_file(conn, path, filename)
  end

  def open_file(path, function \\ nil) do
    case cache_store().open_file(path, function) do
      {:ok, f} ->
        {:ok, f}

      {:error, :enoent} ->
        with {:ok, tmp_path} <- Briefly.create(),
             :ok <- remote_store().download_file(path, tmp_path),
             :ok <- cache_store().put_file(path, tmp_path, MIME.from_path(path)),
             :ok <- File.rm(tmp_path) do
          cache_store().open_file(path, function)
        end

      otherwise ->
        otherwise
    end
  end

  def delete_file(path) do
    with result when result in [:ok, {:error, :enoent}] <- cache_store().delete_file(path),
         :ok <- remote_store().delete_file(path) do
      :ok
    end
  end

  defp config do
    Application.get_env(:asciinema, __MODULE__)
  end

  defp remote_store do
    Keyword.get(config(), :remote_store)
  end

  defp cache_store do
    Keyword.get(config(), :cache_store)
  end
end
