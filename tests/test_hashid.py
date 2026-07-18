from desisherlock.modules import hashid


def test_md5_positive():
    result = hashid.identify_result("5f4dcc3b5aa765d61d8327deb882cf99")
    assert result["identified"] is True
    formats = [m["format"] for m in result["matches"]]
    assert any("MD5" in f for f in formats)


def test_sha1_positive():
    result = hashid.identify_result("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    assert result["identified"] is True
    assert result["matches"][0]["format"] == "SHA-1"


def test_sha256_positive():
    value = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    result = hashid.identify_result(value)
    assert result["identified"] is True
    assert result["matches"][0]["format"] == "SHA-256"


def test_sha512_positive():
    value = "a" * 128
    result = hashid.identify_result(value)
    assert result["identified"] is True
    assert result["matches"][0]["format"] == "SHA-512"


def test_bcrypt_positive():
    value = "$2b$12$KIXQZ8Z8Z8Z8Z8Z8Z8Z8ZuQZ8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8Z8"
    result = hashid.identify_result(value)
    assert result["identified"] is True
    assert result["matches"][0]["format"] == "bcrypt"


def test_unix_crypt_sha512_positive():
    value = "$6$" + "a" * 8 + "$" + "b" * 86
    result = hashid.identify_result(value)
    assert result["identified"] is True
    assert "SHA-512" in result["matches"][0]["format"]


def test_wrong_length_hex_is_not_misidentified():
    # 33 hex chars - one longer than MD5 (32) and nowhere near any known
    # digest length. Must NOT be reported as MD5 or anything else.
    value = "a" * 33
    result = hashid.identify_result(value)
    assert result["identified"] is False
    assert result["matches"] == []


def test_non_hex_garbage_is_not_identified():
    result = hashid.identify_result("not a hash at all!!")
    assert result["identified"] is False


def test_empty_string_is_not_identified():
    result = hashid.identify_result("")
    assert result["identified"] is False


def test_malformed_bcrypt_prefix_rejected():
    # Right prefix, wrong overall shape - should not be force-matched.
    result = hashid.identify_result("$2b$12$tooshort")
    assert result["identified"] is False
