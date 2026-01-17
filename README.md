# 🕵️‍♂️ G.I.D Secure Terminal

![Project Banner](https://img.shields.io/badge/Security-Level%205-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Encryption](https://img.shields.io/badge/Encryption-RSA%20%2B%20AES-green?style=for-the-badge)

> **"Turn your terminal into a Hollywood-style, military-grade encrypted communication channel."**

**G.I.D Secure Terminal** is a Python-based chat application that combines a cinematic **Cyberpunk/Matrix interface** with real-world **End-to-End Encryption (E2EE)** using RSA-2048 and AES standards.

---

## 📺 As Seen on YouTube
This project was built live! Watch the full tutorial on how it works:
**https://youtu.be/sRpcmGFPoj0**

---

## ⚡ Features

### 🖥️ The Interface (UI)
- **Matrix Rain Boot Sequence:** A cinematic start-up effect.
- **Security Protocol Puzzle:** A binary matrix authentication puzzle (Parity Bit Logic) required to access the system.
- **Responsive Design:** Automatically centers text based on your terminal width.
- **Visual Feedback:** Color-coded logs (Green for success, Red for danger, Yellow for processing).

### 🔒 The Security (Cryptography)
- **Hybrid Encryption:** Uses **AES** for message encryption and **RSA-2048** for key exchange.
- **End-to-End Encryption (E2EE):** The server **cannot** read messages. It only routes encrypted blobs.
- **Dynamic Key Generation:** New RSA keys are generated in RAM every time the client starts.
- **Public Key Infrastructure:** Agents register their public keys with the server upon connection.

### 📡 The Network
- **Socket Programming:** Built from scratch using Python's `socket` and `threading`.
- **Offline Messaging (Store & Forward):** If the target agent is offline, the server stores encrypted messages and delivers them instantly upon reconnection.
- **Multi-Client Support:** The server handles multiple agents simultaneously.

---

## 🛠️ Installation

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/YourUsername/GID-Secure-Terminal.git](https://github.com/YourUsername/GID-Secure-Terminal.git)
   cd GID-Secure-Terminal
