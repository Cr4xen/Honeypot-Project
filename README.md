# 🕵️‍♂️ rust-honeypot

![Rust](https://img.shields.io/badge/Rust-2021-orange?style=for-the-badge&logo=rust)
![Tokio](https://img.shields.io/badge/Tokio-Async-blue?style=for-the-badge&logo=tokio)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Project-Active-success?style=for-the-badge)

<p align="center">
  <img src="https://github.com/Cr4xen/rust-honeypot/assets/animation/honeypot.gif" width="400" alt="honeypot animation">
</p>

> **rust-honeypot** is an intermediate-level cybersecurity project built in Rust using **Tokio**.  
> It emulates simple **SSH**, **HTTP**, and **Telnet** services to collect and log intrusion attempts for research or analysis.

---

## ⚙️ Features

- **Asynchronous, multi-port listener** (configurable)
- **Protocol fingerprinting** for SSH / HTTP / Telnet
- **Deceptive responses** (fake banners, login prompts)
- **JSONL-based logging** for easy integration with SIEM tools
- Designed for **Threat Intelligence** and **Malware Behavior Analysis**

---

## 🧰 Requirements

- Rust toolchain (`rustup`, `cargo`)
- Linux recommended for privileged ports (<1024)
- `sudo` required for ports like 22, 80, or 23

---

## 🚀 Build and Run

```bash
# Clone the repository
git clone https://github.com/Cr4xen/rust-honeypot.git
cd rust-honeypot

# Build in release mode
cargo build --release
