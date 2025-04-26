# 🛡️ CPS633 — Advanced Cybersecurity Labs Portfolio

Welcome to my cybersecurity portfolio for CPS633! This repository highlights labs on real-world security attacks, cryptographic implementations, network exploits, tunneling, and firewall evasion.

---

## 📚 Table of Contents
- [Lab 1: Spectre Attack Analysis](#lab-1-spectre-attack-analysis)
- [Lab 2: Secret-Key Encryption](#lab-2-secret-key-encryption)
- [Lab 3: PKI Infrastructure Setup](#lab-3-pki-infrastructure-setup)
- [Lab 4: RSA Algorithm Implementation](#lab-4-rsa-algorithm-implementation)
- [Lab 5: Buffer Overflow Exploit](#lab-5-buffer-overflow-exploit)
- [Lab 6: Packet Sniffing & Spoofing](#lab-6-packet-sniffing--spoofing)
- [Lab 7: VPN Tunnel Setup](#lab-7-vpn-tunnel-setup)
- [Lab 8: Firewall Evasion with SSH](#lab-8-firewall-evasion-with-ssh)
- [Tech Stack](#tech-stack)
- [Contact](#contact)

---

## Lab 1: Spectre Attack Analysis 👻
- Simulated a Spectre-style CPU side-channel attack.
- Extracted protected memory by exploiting speculative execution.
- **Tools:** C, Assembly, Flush+Reload Timing, Linux.

---

## Lab 2: Secret-Key Encryption 🔒
- Performed AES-256-CBC encryption and decryption with OpenSSL.
- Demonstrated secure key/IV management and padding practices.
- **Tools:** OpenSSL, Linux CLI.

---

## Lab 3: PKI Infrastructure Setup 🔏
- Built a self-signed CA and issued X.509 certificates.
- Enabled SSL/TLS handshakes on a sample service.
- **Tools:** OpenSSL, X.509, Linux.

---

## Lab 4: RSA Algorithm Implementation 🔑
- Programmed RSA key generation, encryption, and decryption.
- Emphasized modular arithmetic and cryptographic best practices.
- **Tools:** Python, Big Integer Math.

---

## Lab 5: Buffer Overflow Exploit 💥
- Crafted payloads to overflow a buffer and hijack program control flow.
- Demonstrated attack via vulnerable C programs.
- **Tools:** C, GDB Debugger, Linux (with disabled security features).

---

## Lab 6: Packet Sniffing & Spoofing 📡
- Sniffed live packets using Scapy and libpcap.
- Forged spoofed ICMP and ARP packets.
- **Tools:** Python (Scapy), TCPdump, Wireshark.

---

## Lab 7: VPN Tunnel Setup 🌐
- Created a custom VPN using TUN/TAP virtual interfaces.
- Connected Docker containers securely through IP tunneling.
- **Tools:** Linux TUN/TAP, Docker, TCP/UDP sockets.

---

## Lab 8: Firewall Evasion with SSH 🚀
- Bypassed firewall rules using SSH static and dynamic port forwarding.
- Established SOCKS5 proxy tunneling for hidden web access.
- **Tools:** SSH, iptables, TCPdump, Proxy Settings.

---

## 🛠️ Tech Stack

| Technology        | Purpose                           |
|:------------------|:-----------------------------------|
| C, Python, Assembly | Programming and Exploit Development |
| OpenSSL, X.509    | Cryptography, PKI Infrastructure   |
| Scapy, TCPdump, Wireshark | Network Sniffing and Packet Crafting |
| Docker, Linux TUN/TAP | Virtualized Environments and Tunneling |
| GDB, Unix Tools   | Debugging, Automation, Scripting    |
| SSH, Firewalls    | Tunneling and Firewall Evasion     |

---

## 📬 Contact

- **Portfolio:** [hetuvpatel.github.io/hetu-patel-portfolio](https://hetuvpatel.github.io/hetu-patel-portfolio)
- **GitHub:** [github.com/Patel-Hetu](https://github.com/Patel-Hetu)
- **Email:** [hetu.patel@torontomu.ca](mailto:hetu.patel@torontomu.ca)

---

> _"Securing the future, one lab at a time."_ 🔐🚀
