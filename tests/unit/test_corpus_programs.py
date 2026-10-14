from pathlib import Path

import pytest

from aletheia.corpus.lint import lint_program

PROGRAMS = ("crc32tool", "adlerfletch", "hashtable", "b64", "cmd-dispatch")


@pytest.mark.parametrize("program", PROGRAMS)
def test_authored_program_meets_source_policy(program):
    directory = Path("corpus/tierA") / program
    assert (directory / "tests/test.c").is_file()
    assert (directory / "Makefile").is_file()
    assert lint_program(directory) == []
