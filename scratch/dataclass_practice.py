from dataclasses import dataclass

@dataclass
class LogEvent:
    month: str
    day: int
    time: str
    process: str
    username: str

event = LogEvent(
    month="Aug",
    day=6,
    time="09:15:22",
    process="sshd",
    username="admin",
)

print(event)
print()

print("Month    : ", event.month)
print("Day      : ", event.day)
print("Time     : ", event.time)
print("Process  : ", event.process)
print("Username : ", event.username)

event = {
    "month": "Aug",
    "day": 6,
    "time": "09:15:22",
    "process": "sshd",
    "username": "admin",
}

print()
print("Month    : ", event["month"])
print("Day      : ", event["day"])
print("Time     : ", event["time"])
print("Process  : ", event["process"])
print("Username : ", event["username"])
