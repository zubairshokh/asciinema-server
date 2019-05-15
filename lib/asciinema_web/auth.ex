defmodule AsciinemaWeb.Auth do
  import Plug.Conn
  import Phoenix.Controller, only: [put_flash: 3, redirect: 2]
  import AsciinemaWeb.Plug.ReturnTo
  alias Plug.Conn
  alias Asciinema.Accounts.User
  alias Asciinema.Accounts
  alias Asciinema.Repo

  @user_key "warden.user.user.key"
  @one_year_in_secs 31_557_600

  def init(opts) do
    opts
  end

  def call(%Conn{assigns: %{current_user: %User{}}} = conn, _opts) do
    conn
  end

  def call(%Conn{req_headers: header_list} = conn, _opts) do
    user_id = get_session(conn, @user_key)
    user_from_db = user_id && Repo.get(User, user_id)

    case user_from_db do
      nil ->
        with {:ok, user} <- create_or_get_user(header_list) do
          __MODULE__.log_in(conn, %User{} = user)
        else
          {:error, message} -> error_case(conn, message)
        end

      user ->
        set_user_context(user)
        assign(conn, :current_user, user)
    end
  end

  defp create_session(conn, user) do
    token = user |> Accounts.login_token()

    conn
    |> put_session(:login_token, token)
  end

  defp set_user_context(user) do
    Sentry.Context.set_user_context(%{id: user.id, username: user.username, email: user.email})
  end

  defp create_or_get_user(header_list) do
    case List.keyfind(header_list, "x-amzn-oidc-data", 0) do
      nil ->
        {:error, :not_found}

      {_, jwt_token} ->
        with {:ok, payload} <- get_payload(jwt_token) do
          case get_user_by_email(Map.get(payload, "email")) do
            nil -> {:ok, create_user(payload)}
            user -> {:ok, user}
          end
        else
          _ -> {:error, :payload_error}
        end
    end
  end

  defp create_user(%{"email" => email, "sub" => user_name}) do
    case Accounts.create_user(%{email: email, username: user_name}) do
      {:ok, user} -> user
      _ -> nil
    end
  end

  defp get_user_by_email(email), do: Asciinema.Accounts.get_user_by_email(email)

  defp get_payload(jwt_token) do
    jwt_token
    |> String.split(".")
    |> Enum.at(1)
    |> decode()
    |> Poison.decode()
  rescue
    error -> {:error, :token_error}
  end

  defp decode(payload), do: Base.decode64!(payload)

  defp error_case(conn, :not_found), do: do_error(conn, "Amazon JWT Not found")
  defp error_case(conn, :payload_error), do: do_error(conn, "Jwt Token Error")

  defp do_error(conn, message) do
    conn
    |> assign(:current_user, nil)
    |> put_flash(:error, message)
  end

  def require_current_user(%Conn{assigns: %{current_user: %User{}}} = conn, _) do
    conn
  end

  def require_current_user(conn, opts) do
    msg = Keyword.get(opts, :flash, "Please log in first.")

    conn
    |> save_return_path
    |> put_flash(:info, msg)
    |> redirect(to: "/login/new")
    |> halt
  end

  def require_admin(%Conn{assigns: %{current_user: %User{is_admin: true}}} = conn, _) do
    conn
  end

  def require_admin(conn, _) do
    conn
    |> put_flash(:error, "Access denied.")
    |> redirect(to: "/")
    |> halt()
  end

  def log_in(conn, %User{} = user) do
    user = user |> User.login_changeset() |> Repo.update!()

    conn
    |> put_session(@user_key, user.id)
    |> put_resp_cookie("auth_token", user.auth_token, max_age: @one_year_in_secs)
    |> assign(:current_user, user)
  end

  def log_out(conn) do
    conn
    |> delete_session(@user_key)
    |> delete_resp_cookie("auth_token")
    |> assign(:current_user, nil)
  end

  def get_basic_auth(conn) do
    with ["Basic " <> auth] <- get_req_header(conn, "authorization"),
         # workaround for 1.3.0-1.4.0 client bug
         auth = String.replace(auth, ~r/^%/, ""),
         {:ok, username_password} <- Base.decode64(auth),
         [username, password] <- String.split(username_password, ":") do
      {username, password}
    else
      _ -> nil
    end
  end

  def put_basic_auth(conn, nil, nil) do
    conn
  end

  def put_basic_auth(conn, username, password) do
    auth = Base.encode64("#{username}:#{password}")
    put_req_header(conn, "authorization", "Basic " <> auth)
  end
end
