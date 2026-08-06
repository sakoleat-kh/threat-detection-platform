# Authentication Log Notes

## Syslog Structure

Month | Day | Time | Host | Process | Message

Example:
Aug 6 09:15:22 ubuntu sshd[2543]: Failed password for invalid user admin from 192.168.1.15 port 51234 ssh2

---

## Processes Found

- sshd 
- sudo
- CRON 
- systemd-logind
- ...

---

## Failed Password Examples

1.
2.
3.

---

## Accepted Password Example

1.
2.
3.

---

## Invalid User Examples

1.
2.
3.

---

## Notes from First 50 Lines

- Most authentication events come from sshd.
- CROM jobs appear regularly.
- sudo logs record privilege escalation.
- Failed logins include the source IP.
