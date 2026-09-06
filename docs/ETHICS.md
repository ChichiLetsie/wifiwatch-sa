# WiFiWatch SA — Ethics, Safety & Legal Statement

WiFiWatch SA is an open educational and defensive awareness platform designed to assist South African communities (including commuters, township business hubs, students, and mall visitors) in understanding public Wi-Fi attack vectors like Evil Twins, Rogue Access Points, and ARP spoofing.

The tool adheres strictly to the following principles:

### 1. Synthetic-First by Design
All risk scores, detection logic, visualisations, and metrics run by default against an onboard synthetic data generator. No physical network interface needs to be placed into promiscuous or monitor mode to use or evaluate this platform.

### 2. Explicit Authorisation for Real Scanning
Any packet-level or real capture utilities provided are optional, strictly isolated, and restricted solely to networks the user owns or has explicit, written permission to test.
- The software enforces an interactive confirmation gate: `Do you own this network or have written authorization to test it? [y/N]`.
- If permission is denied or indeterminate, the scan halts immediately.

### 3. Purely Defensive and Observational
WiFiWatch SA contains **no attack code**:
- No deauthentication injection frames.
- No password brute-forcing or cracking tools (WPA/WPA2/WPA3 handshake crackers).
- No payload alteration, packet injection, or MITM interception.

### 4. Zero Payload / Content Collection
Under no circumstances does WiFiWatch SA collect, inspect, or log HTTP/HTTPS payload data, credentials, user traffic, or application payloads. Inspection is confined strictly to network-layer and 802.11 management/beacon metadata:
- SSID names
- BSSID / MAC addresses
- Broadcast signal strengths (RSSI)
- Advertised security standards (Open, WEP, WPA2, WPA3)
- Standard ARP broadcast timing and frequency

### 5. Responsible Handling of Community Data
All mock township scenarios, stations, and retail centres use generalized or synthetic datasets. No identifiable individual data or private residential networks are mapped or exposed.