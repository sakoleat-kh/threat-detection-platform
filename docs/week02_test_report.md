============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /home/sakol/Project/threat-detection-platform/venv/bin/python
cachedir: .pytest_cache
rootdir: /home/sakol/Project/threat-detection-platform
collecting ... collected 19 items

tests/test_linux_parser.py::test_failed_password PASSED                  [  5%]
tests/test_linux_parser.py::test_accepted_password PASSED                [ 10%]
tests/test_linux_parser.py::test_invalid_user PASSED                     [ 15%]
tests/test_linux_parser.py::test_garbage_line_returns_none PASSED        [ 21%]
tests/test_linux_parser.py::test_user_added PASSED                       [ 26%]
tests/test_linux_parser.py::test_december_january_year_rollover PASSED   [ 31%]
tests/test_linux_parser.py::test_sudo_command PASSED                     [ 36%]
tests/test_linux_parser.py::test_sudo_auth_failure PASSED                [ 42%]
tests/test_linux_parser.py::test_unknown_event PASSED                    [ 47%]
tests/test_linux_parser_hardening.py::test_invalid_syslog_timestamp_returns_unknown PASSED [ 52%]
tests/test_linux_parser_hardening.py::test_invalid_iso_timestamp_returns_unknown PASSED [ 57%]
tests/test_linux_parser_hardening.py::test_malformed_failed_password_returns_unknown PASSED [ 63%]
tests/test_linux_parser_hardening.py::test_malformed_accepted_password_returns_unknown PASSED [ 68%]
tests/test_linux_parser_hardening.py::test_malformed_user_added_returns_unknown PASSED [ 73%]
tests/test_linux_parser_hardening.py::test_missinf_ssh_username_returns_unknown PASSED [ 78%]
tests/test_linux_parser_hardening.py::test_incomplete_syslog_line_returns_none PASSED [ 84%]
tests/test_linux_parser_hardening.py::test_completely_garbage_line_returns_none PASSED [ 89%]
tests/test_linux_parser_hardening.py::test_malformed_pid_returns_none PASSED [ 94%]
tests/test_linux_parser_hardening.py::test_incomplete_auth_log_line_returns_none PASSED [100%]

============================== 19 passed in 0.07s ==============================
