**QuantumCryptography**

A C# .NET prototype building a quantum-resistant communication pipeline between a MacBook client and a remote home server using NIST-standardized Post-Quantum Cryptography (PQC).

**Architecture**
- **QuantumCryptography.Shared**: Core cryptographic logic handling ML-KEM-768 key encapsulation via BouncyCastle.
- **QuantumCryptography.Server**: TCP listener designed to run on a home computer, waiting for remote connections.
- **QuantumCryptography.Client**: TCP client running on macOS to initiate the quantum handshake.
