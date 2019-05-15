defmodule Asciinema.SessionControllerTest do
  use AsciinemaWeb.ConnCase
  import Asciinema.Factory
  alias Asciinema.Repo
  alias Asciinema.Accounts

  @jwt_token "x.eyJzdWIiOiIxMDM1MDUyMjI0NTgxMDg5OTI3OTciLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDQuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1iUUM3NXQ2cG9iby9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBMC9jV2kyM2JSWUdZRS9waG90by5qcGciLCJlbWFpbCI6InRpbUBhcmNoc3lzLmlvIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImhkIjoiYXJjaHN5cy5pbyIsImV4cCI6MTU1NzQyMjg3MywiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIn0=.x"

  setup %{conn: conn} do
    {:ok, conn: conn}
  end

  test "successful log-in", %{conn: conn} do
    user = insert(:user, email: "test@example.com", username: "blazko")

    conn = get(conn, "/session/new", t: Accounts.login_token(user))
    assert redirected_to(conn, 302) == "/session/new"

    conn = get(conn, "/session/new")
    assert html_response(conn, 200)

    conn = post(conn, "/session")
    assert redirected_to(conn, 302) == "/~blazko"
    assert get_flash(conn, :info) =~ ~r/welcome/i
  end

  test "successful Login with amazon header jwt", %{conn: conn} do
    conn = put_req_header(conn, "x-amzn-oidc-data", @jwt_token)
    conn = get(conn, "/")

    assert html_response(conn, 200)
  end

  test "INVALID  Login without  amazon header jwt", %{conn: conn} do
    conn = get(conn, "/")
    assert get_flash(conn, :error) =~ "Amazon JWT Not found"
    assert html_response(conn, 200)
  end

  test "INVALID  Login With Invalid  amazon header jwt", %{conn: conn} do
    conn = put_req_header(conn, "x-amzn-oidc-data", "x.invalidtoken.x")
    conn = get(conn, "/")
    assert get_flash(conn, :error) =~ "Jwt Token Error"
    assert html_response(conn, 200)
  end

  test "failed log-in due to invalid token", %{conn: conn} do
    conn = get(conn, "/session/new", t: "nope")
    assert redirected_to(conn, 302) == "/session/new"

    conn = get(conn, "/session/new")
    assert html_response(conn, 200)

    conn = post(conn, "/session")
    assert redirected_to(conn, 302) == "/login/new"
    assert get_flash(conn, :error) =~ ~r/invalid/i
  end

  test "failed log-in due to account removed", %{conn: conn} do
    user = insert(:user, email: "test@example.com", username: "blazko")
    token = Accounts.login_token(user)
    Repo.delete!(user)

    conn = get(conn, "/session/new", t: token)
    assert redirected_to(conn, 302) == "/session/new"

    conn = get(conn, "/session/new")
    assert html_response(conn, 200)

    conn = post(conn, "/session")
    assert redirected_to(conn, 302) == "/login/new"
    assert get_flash(conn, :error) =~ ~r/removed/i
  end

  test "logout", %{conn: conn} do
    user = insert(:user)
    conn = log_in(conn, user)

    conn = delete(conn, "/session")

    assert redirected_to(conn, 302) == "/"
    assert get_flash(conn, :info) =~ ~r/see you/i
  end
end
