# MITRE ATT&CK 战术：数据渗出 Exfiltration

> 本页汇总 19 个技术（Technique）的流量特征、检测方法与缓解措施，供安全分析师在事件研判与处置时参考。
## T1011 Exfiltration Over Other Network Medium
- **适用平台**：Linux, macOS, Windows
- **描述**：Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.  Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

## T1011.001 Exfiltration Over Bluetooth
- **适用平台**：Linux, macOS, Windows
- **描述**：Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel.  Adversaries may choose to do this if they have sufficient access and proximity. Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

## T1020 Automated Exfiltration
- **适用平台**：Linux, macOS, Network Devices, Windows
- **描述**：Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.(Citation: ESET Gamaredon June 2020)   When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

## T1020.001 Traffic Duplication
- **适用平台**：Network Devices, IaaS
- **描述**：Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. (Citation: Cisco Traffic Mirroring)(Citation: Juniper Traffic Mirroring)  Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) or [Patch System Image](https://attack.mitre.org/techniques/T1601/001).(Citation: US-CER

## T1029 Scheduled Transfer
- **适用平台**：Linux, macOS, Windows
- **描述**：Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.  When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) or [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

## T1030 Data Transfer Size Limits
- **适用平台**：Linux, macOS, Windows, ESXi
- **描述**：An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

## T1041 Exfiltration Over C2 Channel
- **适用平台**：ESXi, Linux, macOS, Windows
- **描述**：Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

## T1048 Exfiltration Over Alternative Protocol
- **适用平台**：ESXi, IaaS, Linux, macOS, Network Devices, Office Suite, SaaS, Windows
- **描述**：Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.    Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels.   [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016) On macOS and Linux <code>curl</code> may be used to invoke protocols such as HTTP/S or FTP/S to e

## T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- **适用平台**：Linux, macOS, Windows, ESXi
- **描述**：Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.   Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data.   Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encrypt

## T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- **适用平台**：ESXi, Linux, macOS, Windows
- **描述**：Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.   Asymmetric encryption algorithms are those that use different keys on each end of the channel. Also known as public-key cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. Each end of the communication channels requires a private key (only in the procession of that entity) and the public key of the other entity. The public keys of each entity are exchanged before encrypted communications begin.   Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often

## T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol
- **适用平台**：ESXi, Linux, macOS, Network Devices, Windows
- **描述**：Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.(Citation: copy_cmd_cisco)  Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields.

## T1052 Exfiltration Over Physical Medium
- **适用平台**：Linux, macOS, Windows
- **描述**：Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

## T1052.001 Exfiltration over USB
- **适用平台**：Linux, Windows, macOS
- **描述**：Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

## T1537 Transfer Data to Cloud Account
- **适用平台**：IaaS, Office Suite, SaaS
- **描述**：Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service.  A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.(Citation: TLDRSec AWS Attacks)  Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts, such as creating anonymou

## T1567 Exfiltration Over Web Service
- **适用平台**：ESXi, Linux, macOS, Office Suite, SaaS, Windows
- **描述**：Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.  Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.

## T1567.001 Exfiltration to Code Repository
- **适用平台**：ESXi, Linux, macOS, Windows
- **描述**：Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection.  Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network.

## T1567.002 Exfiltration to Cloud Storage
- **适用平台**：ESXi, Linux, macOS, Windows
- **描述**：Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet.  Examples of cloud storage services include Dropbox and Google Docs. Exfiltration to these cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service.

## T1567.003 Exfiltration to Text Storage Sites
- **适用平台**：Linux, macOS, Windows, ESXi
- **描述**：Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as <code>pastebin[.]com</code>, are commonly used by developers to share code and other information.    Text storage sites are often used to host malicious code for C2 communication (e.g., [Stage Capabilities](https://attack.mitre.org/techniques/T1608)), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely.(Citation: Pastebin EchoSec)  **Note:** This is distinct from [Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001), which highlight access to code repositories via APIs.

## T1567.004 Exfiltration Over Webhook
- **适用平台**：ESXi, Linux, macOS, Office Suite, SaaS, Windows
- **描述**：Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server.(Citation: RedHat Webhooks) Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello.(Citation: Discord Intro to Webhooks) When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application.   Adversaries may link an adversary-owned environment to a vi
