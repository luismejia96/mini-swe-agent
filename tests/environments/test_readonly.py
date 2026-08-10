import pytest

from minisweagent.environments.readonly import ReadOnlyLocalEnvironment, ReadOnlyLocalEnvironmentConfig


def test_readonly_config_defaults():
    config = ReadOnlyLocalEnvironmentConfig()
    assert config.cwd == ""
    assert config.timeout == 30
    assert "rm" in config.blocked_commands
    assert ">" in config.blocked_commands


def test_readonly_allows_read_commands():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("echo hello")
    assert result["returncode"] == 0
    assert "hello" in result["output"]


def test_readonly_allows_ls():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("ls /tmp")
    assert result["returncode"] == 0


def test_readonly_blocks_rm():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("rm -rf /tmp/something")
    assert result["returncode"] == 1
    assert "ReadOnlyLocalEnvironment" in result["output"]
    assert "rm" in result["output"]


def test_readonly_blocks_redirect_operator():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("echo hi > /tmp/file.txt")
    assert result["returncode"] == 1
    assert "ReadOnlyLocalEnvironment" in result["output"]


def test_readonly_blocks_append_operator():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("echo hi >> /tmp/file.txt")
    assert result["returncode"] == 1
    assert "ReadOnlyLocalEnvironment" in result["output"]


def test_readonly_blocks_mv():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("mv /tmp/a /tmp/b")
    assert result["returncode"] == 1
    assert "ReadOnlyLocalEnvironment" in result["output"]


def test_readonly_blocks_chmod():
    env = ReadOnlyLocalEnvironment()
    result = env.execute("chmod 777 /tmp/test")
    assert result["returncode"] == 1
    assert "ReadOnlyLocalEnvironment" in result["output"]


@pytest.mark.parametrize(
    ("command", "should_block"),
    [
        ("cat /etc/hostname", False),
        ("grep -r foo /etc/hostname", False),
        ("find /tmp -name '*.py'", False),
        ("rm /tmp/x", True),
        ("rmdir /tmp/x", True),
        ("mv /a /b", True),
        ("dd if=/dev/zero of=/dev/sda", True),
        ("chmod 777 /tmp", True),
        ("chown root /tmp", True),
        ("echo hi > /tmp/f", True),
        ("echo hi >> /tmp/f", True),
        ("tee /tmp/f", True),
    ],
)
def test_readonly_parametrized(command, should_block):
    env = ReadOnlyLocalEnvironment()
    result = env.execute(command)
    if should_block:
        assert result["returncode"] == 1
        assert "ReadOnlyLocalEnvironment" in result["output"]
    else:
        assert "ReadOnlyLocalEnvironment" not in result["output"]


def test_readonly_tee_word_boundary():
    """tee should be blocked as a command but not as a substring in filenames."""
    env = ReadOnlyLocalEnvironment()
    # Should block the `tee` command
    assert env.execute("tee /tmp/file")["returncode"] == 1
    # Should NOT block a filename that contains 'tee' as a substring
    result = env.execute("cat /etc/hostname")
    assert "ReadOnlyLocalEnvironment" not in result["output"]


    env = ReadOnlyLocalEnvironment()
    vars_ = env.get_template_vars()
    assert vars_["readonly_mode"] is True
