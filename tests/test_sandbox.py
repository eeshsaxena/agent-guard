from agentguard import sandbox


def _which(*present):
    found = set(present)
    return lambda name: f"/usr/bin/{name}" if name in found else None


def test_build_linux_prefers_bwrap():
    argv, msg = sandbox.build_sandbox_command(
        ["python", "app.py"], ["/home/u/project"],
        system="Linux", which=_which("bwrap", "firejail"),
    )
    assert msg == ""
    assert argv[0] == "bwrap"
    assert "--bind" in argv
    assert argv[argv.index("--bind") + 1] == "/home/u/project"
    assert argv[-2:] == ["python", "app.py"]
    assert "--" in argv


def test_build_linux_falls_back_to_firejail():
    argv, msg = sandbox.build_sandbox_command(
        ["ls"], ["/home/u/project"],
        system="Linux", which=_which("firejail"),
    )
    assert argv[0] == "firejail"
    assert "--whitelist=/home/u/project" in argv
    assert argv[-1] == "ls"


def test_build_linux_no_tool_refuses():
    argv, msg = sandbox.build_sandbox_command(
        ["ls"], ["/home/u"], system="Linux", which=_which(),
    )
    assert argv is None
    assert "Refusing to run" in msg
    assert "bwrap" in msg


def test_bwrap_binds_every_root():
    argv = sandbox.linux_bwrap_args(["true"], ["/a", "/b"])
    binds = [argv[i + 1] for i, t in enumerate(argv) if t == "--bind"]
    assert binds == ["/a", "/b"]
    assert argv[argv.index("--chdir") + 1] == "/a"


def test_macos_profile_denies_by_default_and_allows_roots():
    profile = sandbox.macos_profile(["/Users/u/project", "/Users/u/scratch"])
    assert "(deny default)" in profile
    assert '(subpath "/Users/u/project")' in profile
    assert '(subpath "/Users/u/scratch")' in profile
    assert "file-write*" in profile


def test_macos_build_uses_inline_profile():
    argv, msg = sandbox.build_sandbox_command(
        ["echo", "hi"], ["/Users/u/project"],
        system="Darwin", which=_which("sandbox-exec"),
    )
    assert argv[0] == "sandbox-exec"
    assert argv[1] == "-p"
    assert "(deny default)" in argv[2]
    assert argv[-2:] == ["echo", "hi"]


def test_macos_no_tool_refuses():
    argv, msg = sandbox.build_sandbox_command(
        ["ls"], ["/Users/u"], system="Darwin", which=_which(),
    )
    assert argv is None
    assert "sandbox-exec" in msg


def test_windows_is_honestly_unsupported():
    argv, msg = sandbox.build_sandbox_command(
        ["dir"], ["C:/Users/u"], system="Windows", which=_which("bwrap"),
    )
    assert argv is None
    assert "not available on Windows" in msg
    assert "Docker" in msg or "WSL" in msg


def test_unknown_platform_refuses():
    argv, msg = sandbox.build_sandbox_command(["ls"], [], system="Plan9", which=_which())
    assert argv is None
    assert "Plan9" in msg


def test_macos_profile_without_roots_omits_the_writable_roots_block():
    # With no roots configured the profile still denies by default and keeps the
    # base reads, but grants no read+write anywhere in user space.
    profile = sandbox.macos_profile([])
    assert "(deny default)" in profile
    assert "file-read* file-write*" not in profile
    assert '(literal "/dev/null")' in profile
