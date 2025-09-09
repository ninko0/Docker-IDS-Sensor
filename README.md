# IDS, Honeypot, and Packet Capture Deployment with Docker

This project provides a set of Docker configurations to quickly deploy a network security monitoring stack. It includes an Intrusion Detection System (IDS), a network analysis framework, a packet capture tool, and a honeypot.

**Components:**
*   **IDS:** [Suricata](https://suricata.io/)
*   **Network Analyzer:** [Zeek](https://zeek.org/) (formerly Bro)
*   **Packet Capture & Viewer:** [Arkime](https://arkime.com/) (formerly Moloch)
*   **Honeypot:** [OpenCanary](https://github.com/thinkst/opencanary)

---

## ⚠️ Security Analysis & Important Warnings

This repository is intended as a template for rapid deployment and **is not a production-ready solution**. A thorough review of all configurations is essential before deployment.

*   **Critical: Missing Honeypot Configuration:** The `init-and-start_IDS_Honeypot.sh` script attempts to start OpenCanary using a `docker-compose.yml` file that is **missing** from the `opencanary-docker/` directory. The honeypot component is therefore **non-functional** out of the box.

*   **High-Risk: Default Arkime Password:** The startup script sets a default password for the Arkime `admin` user to `'MonMotdepasse'`. This password **must be changed immediately** during setup to prevent unauthorized access.

*   **High-Risk: Hardcoded Configuration:** Numerous critical values are hardcoded across multiple files. These include network interfaces, IP addresses, and service URLs. Deploying this without modification will likely fail and could create security vulnerabilities.

---

## Prerequisites

*   **Software:** Docker and Docker Compose must be installed on your system.
*   **Knowledge:** A solid understanding of Docker, computer networking (subnets, gateways, network interfaces), and the basics of the security tools listed above is required.
*   **SIEM:** Arkime requires a connection to an Elasticsearch or OpenSearch instance. The configuration defaults to `http://localhost:9200`. You must provide your own SIEM or use the commented-out OpenSearch `docker-compose` file (not included in this repository) as a starting point.

---

## Configuration

Before you begin, you must customize the configuration files to match your environment.

### 1. Network Configuration

The script creates a `macvlan` network for the honeypot. You must edit `init-and-start_IDS_Honeypot.sh` and set the correct values for your network:

*   `--subnet`: The subnet for the macvlan network (e.g., `192.168.1.0/24`).
*   `--gateway`: The gateway for the macvlan network (e.g., `192.168.1.1`).
*   `parent`: Your host's primary network interface (e.g., `eth0`, `ens192`).

### 2. Service-Specific Configuration

You must change the network interface name (default: `eno1`) in the following files:

*   `suricata-docker/docker-compose.yml`
*   `zeek-docker/docker-compose.yml`
*   `arkime-docker/config.capture.ini`
*   `arkime-docker/config.viewer.ini`

### 3. Arkime Configuration

*   **SIEM URL:** Change the `elasticsearch` URL in the following files to point to your Elasticsearch or OpenSearch instance:
    *   `arkime-docker/docker-compose.yml` (in the `arkime-init` service command)
    *   `arkime-docker/config.capture.ini`
    *   `arkime-docker/config.viewer.ini`
*   **Sensor Name:** In `arkime-docker/docker-compose.yml`, change the capture host name from `sensor-test` to a name that fits your environment.

### 4. Suricata Custom Rules

*   Edit `suricata-docker/local.rules` to add your own custom rules. The default rule contains a placeholder IP that should be changed.

### 5. Zeek Custom Scripts

*   Review the scripts in `zeek-docker/scripts/`. The `canary.zeek` script contains a hardcoded IP address that needs to be updated.

---

## Deployment

1.  **Review and Edit:** Complete all the configuration steps outlined above.
2.  **Run the Script:** Execute the startup script from the root of the repository:
    ```bash
    sudo ./init-and-start_IDS_Honeypot.sh
    ```
3.  **Set Arkime Password:** Immediately after the script finishes, change the default Arkime password. **Do not forget this step.**
    ```bash
    sudo docker exec -it arkime-viewer /opt/arkime/bin/arkime_add_user.sh admin "Admin User" 'YOUR_NEW_SECURE_PASSWORD' --admin
    ```

---

## Disclaimer

This project is a proof-of-concept and is provided as-is. It is a starting point for building a custom monitoring solution and is not designed to be a "turnkey" product. The user assumes all responsibility for securing and in maintaining their deployment.
