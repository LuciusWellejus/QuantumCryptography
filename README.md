# QuantumCryptography

A C# .NET architecture building a quantum-resistant communication pipeline between a MacBook client and a remote home server using NIST-standardized Post-Quantum Cryptography (PQC).

## Architecture
- **QuantumCryptography.Shared**: Core cryptographic logic handling ML-KEM-768 key encapsulation via BouncyCastle and symmetric AES-256-GCM envelope sealing.
- **QuantumCryptography.Server**: Full-duplex TCP listener designed to run on a home computer, capable of receiving text and streaming large data chunks simultaneously.
- **QuantumCryptography.Client**: Full-duplex TCP client running on macOS to initiate the quantum handshake and stream script/file payloads safely.

## Technical Features
- **Post-Quantum Security:** Implements **ML-KEM-768** to protect your initial key exchange from harvesting attacks intended for future quantum computers.
- **Full-Duplex Communication:** Uses parallel background threads (`Task.Run`) so both machines can send and receive messages at the exact same time without freezing.
- **Memory-Safe File Streaming:** Transmits large files, code scripts, or documents in continuous **64KB chunks** instead of loading the entire file into RAM, keeping the app fast and lightweight.
- **Authenticated Integrity:** Every single packet is encrypted with **AES-GCM**. If a packet is tampered with or corrupted on the internet, it is instantly discarded.


## How the Communication Pipeline Works

```
[ MacBook Client ]                                     [ Home Server ]
|                                                     |
| -------- 1. TCP Connection Initiated -------------> |
| <------- 2. Transmits Public ML-KEM-768 Key ------- |
|                                                     |
[Generates Secret]                                           |
[Encapsulates Key]                                           |
| -------- 3. Returns Encrypted Ciphertext ---------> |
|                                              [Extracts Secret]
|                                              [Derives AES Key]
[Derives AES Key]                                            |
|                                                     |
================= SECURE QUANTUM-SAFE AES-GCM TUNNEL OPEN =================
|                                                     |
| <------- 4. Asynchronous Chat & File Streaming ----> |
```


When data passes through the active tunnel, it is processed via structured packet headers:
- **Type `0`:** Direct Chat/Source Code text message.
- **Type `1`:** File Transfer Metadata (Spawns a new file on the server drive).
- **Type `2`:** Continuous 64KB File Chunk Material.
- **Type `3`:** Stream Termination Notice (Safely closes and saves the file on disk).

---

## How to Set Up and Connect Remotely

### 1. Compile the Application
You can build production-ready packages for both of your machines directly from your MacBook terminal:

```bash
# Compile the Server for a Windows host computer
dotnet publish src/QuantumCryptography.Server -c Release -r win-x64 --self-contained

# Compile the Client for your Apple Silicon MacBook
dotnet publish src/QuantumCryptography.Client -c Release -r osx-arm64 --self-contained
```

### 2. Configure Remote Internet Paths
To connect your MacBook from an external network to your home computer:
1. Log into your home router's admin panel.
2. Create a **Port Forwarding rule** that maps incoming traffic on external port **`8080 (TCP)`** directly to the local network IP of your home computer (e.g., `192.168.1.X`).
3. Find your public internet IP address using a service like *whatsmyip.org*.
4. Open `src/QuantumCryptography.Client/TcpClient.cs` on your MacBook and change `string serverIp = "127.0.0.1";` to your public home IP address.

### 3. Launch the Secure Session
Run the server component on your home computer first:
```bash
dotnet run --project src/QuantumCryptography.Server
```

Then, launch the client component on your MacBook:
```bash
dotnet run --project src/QuantumCryptography.Client
```

- Type normally into either window to chat securely.
- To send an entire file or code script, type: `/file <path-to-file>` (e.g., `/file /Users/username/Desktop/script.py`).

---

## Educational Resources & Theoretical Context

To understand the core reason why this software repository is built, it helps to look at the mathematical vulnerability of standard encryption. In public-key cryptography, algorithms like RSA or Diffie-Hellman rely on the fact that factoring massive prime numbers is incredibly slow for classical computers. 

However, quantum computing completely shifts this dynamic. For deeper insights into this vulnerability and how quantum algorithms evolved, check out this firsthand account:

*   **Video:** [Quantum Expert Insight: Peter Shor](https://www.youtube.com/watch?v=6qD9XElTpCE)

### Key Takeaways from the Insight
*   **The Threat Vector:** In 1994, mathematician Peter Shor discovered **Shor's Algorithm**. This specialized quantum algorithm utilizes the properties of quantum computing—such as the discrete Fourier transform—to find periodicity in mathematical structures. This allows a quantum machine to factor exceptionally large numbers exponentially faster than any classical supercomputer.
*   **Breaking Legacy Cryptography:** If a sufficiently large quantum computer runs Shor's algorithm, it can trivially reverse-engineer public keys to extract private keys, effectively breaking modern standard protocols like RSA and Diffie-Hellman.
*   **The Need for ML-KEM:** Because legacy cryptographic systems are vulnerable, security frameworks must adapt. This repository utilizes **ML-KEM-768**, an algorithm constructed to resist Shor's factoring capabilities, ensuring that your data transit parameters remain completely secure in the post-quantum era.