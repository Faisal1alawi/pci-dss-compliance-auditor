import paramiko
import socket
from datetime import datetime

def run_command(client, cmd):
    stdin, stdout, stderr = client.exec_command(cmd)
    output = stdout.read().decode(errors="ignore").strip()
    error = stderr.read().decode(errors="ignore").strip()
    return output, error

def write_section(report_file, title, cmd, output, error):
    report_file.write(f"\n[{title}]\n")
    report_file.write(f"Command: {cmd}\n")
    report_file.write("-" * 60 + "\n")
    if output:
        report_file.write(output + "\n")
    if error:
        report_file.write("\n[Error]\n" + error + "\n")
    report_file.write("-" * 60 + "\n")

def main():
    host = input("Enter target IP: ").strip()
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    report_name = "report.txt"

    try:
        client.connect(
            hostname=host,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )

        print("\n[+] Connected successfully!")
        print(f"[+] Saving report to: {report_name}\n")

        commands = [
            ("System Info", "uname -a"),
            ("Current User", "whoami"),
            ("System Uptime", "uptime"),
            ("Hostname", "hostname"),

            ("SSH Service Status", "systemctl is-active ssh || systemctl is-active sshd"),
            ("Open SSH Port", "ss -tulpen | grep ':22' || netstat -tulpen | grep ':22'"),

            ("Firewall Status (UFW)", "ufw status verbose || true"),
            ("Firewall Rules (iptables)", "iptables -L -n || true"),
            ("Firewall Rules (nftables)", "nft list ruleset || true"),

            ("SSH Security Policy",
             "sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication' || true"),
            ("SSH Config File",
             "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config || true"),

            ("Password Policy (login.defs)",
             "cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN' || true"),
        ]

        with open(report_name, "w", encoding="utf-8") as report:
            report.write("PCI DSS Basic Compliance Scan Report\n")
            report.write(f"Target: {host}\n")
            report.write(f"Time: {datetime.now()}\n")
            report.write("=" * 60 + "\n")

            for title, cmd in commands:
                output, error = run_command(client, cmd)

                print(f"[{title}]")
                if output:
                    print(output)
                if error:
                    print(error)
                print("-" * 60)

                write_section(report, title, cmd, output, error)

        print("\n===== Scan Finished =====")
        print("Report saved as: report.txt")

    except (socket.timeout, paramiko.AuthenticationException) as e:
        print(f"[-] Connection failed: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass

if __name__ == "__main__":
    main()


