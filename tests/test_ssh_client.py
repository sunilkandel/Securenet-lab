"""
Tests for host-key verification in src/ssh_client.py.

Runs a real (in-process) paramiko SSH server on localhost, so the checks
exercise paramiko's actual known_hosts handling rather than a mock.
"""

import socket
import threading

import paramiko
import pytest

from src import ssh_client


class _AcceptAnyKey(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL


@pytest.fixture(scope="module")
def keys():
    return {
        "server": paramiko.RSAKey.generate(2048),
        "impostor": paramiko.RSAKey.generate(2048),
        "client": paramiko.RSAKey.generate(2048),
    }


@pytest.fixture
def server(keys):
    """Start a one-connection SSH server; yields a function to set its key."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    state = {"key": keys["server"]}

    def serve():
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        t = paramiko.Transport(conn)
        t.add_server_key(state["key"])
        try:
            t.start_server(server=_AcceptAnyKey())
            t.accept(5)
        except Exception:
            pass
        finally:
            t.close()

    thread = threading.Thread(target=serve, daemon=True)
    state["port"] = sock.getsockname()[1]
    state["start"] = thread.start
    yield state
    sock.close()
    thread.join(5)


def _files(tmp_path, keys, known_key=None, port=0):
    client_key = tmp_path / "id_rsa"
    keys["client"].write_private_key_file(str(client_key))
    known = tmp_path / "known_hosts"
    if known_key is not None:
        known.write_text(f"[127.0.0.1]:{port} {known_key.get_name()} {known_key.get_base64()}\n")
    else:
        known.write_text("")
    return str(client_key), str(known)


def test_known_host_key_is_accepted(server, keys, tmp_path):
    key_path, known = _files(tmp_path, keys, keys["server"], server["port"])
    server["start"]()
    client = ssh_client.connect("127.0.0.1", server["port"], "u", key_path, known)
    assert client.get_transport().is_active()
    client.close()


def test_unknown_host_key_is_refused(server, keys, tmp_path):
    key_path, known = _files(tmp_path, keys)
    server["start"]()
    with pytest.raises(ssh_client.HostKeyError, match="not in"):
        ssh_client.connect("127.0.0.1", server["port"], "u", key_path, known)
    assert (tmp_path / "known_hosts").read_text() == ""   # nothing auto-added


def test_changed_host_key_is_refused(server, keys, tmp_path):
    key_path, known = _files(tmp_path, keys, keys["server"], server["port"])
    server["key"] = keys["impostor"]                        # target "replaced"
    server["start"]()
    with pytest.raises(ssh_client.HostKeyError, match="CHANGED"):
        ssh_client.connect("127.0.0.1", server["port"], "u", key_path, known)
