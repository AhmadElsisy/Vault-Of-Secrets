import pytest
from password_generator import PasswordGenerator
from constants import SECURITY


def test_normal_length():
    generator = PasswordGenerator(SECURITY["MIN_LENGTH"], n=16)
    pwd = generator.generator()
    assert len(pwd) == 16


def test_min_length():
    generator = PasswordGenerator(SECURITY["MIN_LENGTH"], n=5)
    pwd = generator.generator()
    assert len(pwd) == 12


def test_max_length():
    generator = PasswordGenerator(SECURITY["MIN_LENGTH"], n=SECURITY["MAX_LENGTH"] + 15)
    pwd = generator.generator()
    assert len(pwd) == SECURITY["MIN_LENGTH"]
