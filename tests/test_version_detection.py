import pytest
from flowhound.vulnerabilities.io.version_detection import *

convert_version_to_int_valid = [
    ('1.0.0', 1000000),
    ('1.8.4', 1008004),
    ('1.10.0', 1010000),
    ('0.0.0', 0)
]

convert_version_to_int_invalid = [
    (None, ValueError, '`target_version` must be a non-empty string.'),
    ('', ValueError, '`target_version` must be a non-empty string.'),
    ('1.10', ValueError, '`target_version` must take the form: `x.x.x`.'),
    ('1.10.0.1', ValueError, '`target_version` must take the form: `x.x.x`.')
]

convert_int_to_version_valid = [
    (1000000, '1.0.0'),
    (1008004, '1.8.4'),
    (1010000, '1.10.0'),
    (0, '0.0.0')
]

convert_int_to_version_invalid = [
    ('1.0.0', ValueError, 'Invalid version integer. `target_version` Must be a integer > 0.'),
    ('1000000', ValueError, 'Invalid version integer. `target_version` Must be a integer > 0.'),
    (0, ValueError, 'Invalid version integer. `target_version` Must be a integer > 0.'),
    (None, ValueError, 'Invalid version integer. `target_version` Must be a integer > 0.'),
]


@pytest.mark.parametrize("target_version, result", convert_version_to_int_valid)
def test_convert_version_to_int_valid(target_version, result):
    try:
        conversion = convert_version_to_int(target_version=target_version)
    except Exception as e:
        pytest.fail(str(e))
    
    assert conversion == result


@pytest.mark.parametrize("target_version, error, error_msg", convert_version_to_int_invalid)
def test_convert_version_to_int_invalid(target_version, error, error_msg):
    with pytest.raises(error, match=error_msg):
        convert_version_to_int(target_version=target_version)


@pytest.mark.parametrize("target_version, result", convert_int_to_version_valid)
def test_convert_int_to_version(target_version, result):
    try:
        conversion = convert_int_to_version(target_version=target_version)
    except Exception as e:
        pytest.fail(str(e))
    
    assert conversion == result


@pytest.mark.parametrize("target_version, error, error_msg", convert_int_to_version_invalid)
def test_convert_int_to_version(target_version, error, error_msg):
    with pytest.raises(error, match=error_msg):
        convert_int_to_version(target_version=target_version)