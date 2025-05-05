# 🛡️ Zero Trust Network Prototype

![Zero Trust Network](https://img.shields.io/badge/Security-Zero%20Trust-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Mininet](https://img.shields.io/badge/Mininet-2.3.0-orange)
![OpenFlow](https://img.shields.io/badge/OpenFlow-1.3-brightgreen)
![SDN](https://img.shields.io/badge/SDN-Ryu-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> A comprehensive prototype implementation of a Zero Trust Network architecture using Software-Defined Networking (SDN) principles, built with Python, Mininet, and OpenFlow.

## 📖 Overview

This project implements a Zero Trust Network prototype that follows the "never trust, always verify" security model using Software-Defined Networking principles. Unlike traditional perimeter-based security, Zero Trust enforces strict verification for every network access request regardless of where it originates.

### Key Features

- ✅ **Micro-segmentation**: Network divided into secure zones with distinct security policies
- ✅ **Authentication for all connections**: No implicit trust based on network location
- ✅ **Least privilege access**: Only necessary access rights are granted to authenticated entities
- ✅ **Continuous verification**: Ongoing monitoring and validation of all connections
- ✅ **Default-deny posture**: All access is denied unless explicitly permitted by policy
- ✅ **SDN-based implementation**: Centralized policy enforcement using OpenFlow

## 🏗️ Architecture

The prototype consists of:

1. **Mininet Network Topology**:
   - Trusted zone for internal resources
   - DMZ zone for externally accessible services
   - Untrusted zone for external entities
   - Core infrastructure with authentication and policy services

2. **Ryu SDN Controller**:
   - Zero Trust policy engine
   - Authentication verification
   - Continuous monitoring
   - Dynamic flow management

3. **Zero Trust Services**:
   - Authentication server (validates identities)
   - Policy server (determines access permissions)

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Mininet 2.3.0+
- Ryu SDN Framework
- Open vSwitch with OpenFlow 1.3 support

### Installation

```bash
# Clone this repository
git clone https://github.com/ROHITCRAFTSYT/zero-trust-network.git
cd zero-trust-network

# Install dependencies
pip install -r requirements.txt

# Verify installation
python zero_trust_test.py --skip-deps
```

### Running the Prototype

1. **Start the Ryu controller**:
   ```bash
   ryu-manager zero_trust_controller.py
   ```

2. **Create and run the network**:
   ```bash
   sudo python zero_trust_network.py
   ```

3. **Run the test suite**:
   ```bash
   sudo python zero_trust_test.py
   ```

## 🧪 Testing the Zero Trust Implementation

The test script validates key Zero Trust principles:

- **Authentication verification**: Ensures all connections are authenticated
- **Policy enforcement**: Confirms access is granted only according to policy
- **Micro-segmentation**: Tests isolation between network segments
- **Default-deny behavior**: Verifies unauthorized connections are blocked
- **Continuous verification**: Tests periodic re-authentication requirements

## 🔧 Implementation Details

### Network Topology

```
                       +----------------+
                       |  Core Switch   |
                       +----------------+
                        /      |      \
                       /       |       \
          +-------------+  +-------------+  +-------------+
          |   Trusted   |  |     DMZ     |  |  Untrusted  |
          |   Switch    |  |   Switch    |  |   Switch    |
          +-------------+  +-------------+  +-------------+
                |  |           |  |              |
          +-----+  +----+ +----+  +-----+  +-----+
          |             | |              |  |
   +-----------+  +-----------+  +-----------+
   | Trusted   |  |   DMZ     |  | Untrusted |
   |   Hosts   |  |  Servers  |  |   Hosts   |
   +-----------+  +-----------+  +-----------+
```

### Zero Trust Controller Logic

1. **Default deny all traffic**
2. **Identify and authenticate source**
3. **Verify policy allows the access**
4. **Grant least privilege access**
5. **Monitor and log all activities**
6. **Time-limited access with re-authentication**

## 🔐 Security Considerations

- This is a **prototype** and requires additional hardening for production use
- Authentication mechanisms should be enhanced with MFA for production
- Policy rules should be regularly audited and updated
- Add encryption for all control plane communications
- Implement detailed logging and anomaly detection

## 📚 Additional Resources

- [NIST Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
- [SDN Security Best Practices](https://www.opennetworking.org)
- [Mininet Documentation](http://mininet.org/documentation/)
- [Ryu Controller Framework](https://ryu.readthedocs.io/en/latest/)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

Project Link: [https://github.com/ROHITCRAFTSYT/zero-trust-network](https://github.com/ROHITCRAFTSYT/zero-trust-network)

---

<p align="center">
  Made with ❤️ for better network security
</p>
