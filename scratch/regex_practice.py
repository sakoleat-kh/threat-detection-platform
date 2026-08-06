import re

timestamp = "Aug 6 09:15:22"

timestamp_pattern = re.compile(
    r"(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)

match = timestamp_pattern.search(timestamp)

if match:
    print("===== Timestamp =====")
    print("Month :", match.group("month"))
    print("Day : ", match.group("day"))
    print("Time :", match.group("time"))
else:
    print("Timestamp not found.")

print()

log = (
    "Aug 6 09:15:22 ubuntu sshd[2543]: "
    "Failed password for invalid user admin "
    "from 192.168.1.15 port 51234 ssh2"
)

username_pattern = re.compile(
    r"invalid user (?P<username>\w+)"
)

match = username_pattern.search(log)

if match:
    print("===== Username =====")
    print("Username:", match.group("username"))
else:
    print("Username not found.")