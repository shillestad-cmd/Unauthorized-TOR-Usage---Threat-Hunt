<p align="center">
  <img src="images/00-tor-banner.png" alt="Tor project banner" width="700">
</p>

# Threat Hunt: Unauthorized Tor Browser Usage

## Skills and Tools Demonstrated

- Microsoft Defender for Endpoint
- Microsoft Defender XDR Advanced Hunting
- Microsoft Defender Live Response
- Kusto Query Language (KQL)
- Threat Hunting
- Endpoint Forensic Analysis
- File and Process Event Analysis
- Network Connection Analysis
- Evidence Collection and Review
- Security Telemetry Correlation
- Investigation Timeline Reconstruction
- Acceptable Use Policy Investigation
- Security Findings Documentation and Escalation Recommendations

## Introduction

This project demonstrates a threat hunt into unauthorized Tor Browser installation and use on a simulated company workstation. The investigation used **Microsoft Defender for Endpoint, Advanced Hunting, KQL, and Live Response** to reconstruct an employee’s activity through file records, running programs, network connections, and a collected text file.

Tor, short for **The Onion Router**, is a network designed to improve privacy by routing traffic through intermediary computers called **relays**. Instead of connecting directly to a website, the browser passes traffic through the Tor network with multiple layers of encryption. Each relay removes a layer and forwards the traffic to the next relay, similar to peeling an onion. This design helps prevent a single relay from knowing both the user’s original address and the final destination.

When accessing a regular website, traffic typically passes through an entry relay, a middle relay, and an exit relay. The website sees the exit relay’s address instead of the user’s public IP address. Websites ending in **`.onion`**, called onion services, operate within the Tor network and use a different connection arrangement that does not require an exit relay.

Tor has legitimate uses, including protecting personal privacy, accessing information under censorship, and supporting confidential communication for journalists and their sources. It can also be used to access illicit content. **Using Tor alone does not establish criminal activity.** In this project, the concern was its installation and use on company equipment despite an explicit company policy prohibiting it.

All employee activity was simulated in a controlled lab. The objective was to demonstrate how an analyst can investigate unauthorized software usage, explain the supporting evidence, and document a policy violation without overstating what the evidence proves.

## Threat Scenario: Employee Activity

The scenario involved an employee using a company workstation for unauthorized personal browsing. The organization’s acceptable use policy prohibited Tor installation and use on corporate devices. The employee downloaded Tor Browser, installed it, connected to the Tor network, browsed marketplace-related content, and created a local shopping list.

These actions created a sequence for the threat hunt to investigate: the software appeared on the workstation, its installer ran, browser processes started, network connections followed, and a related text file was created.

### 1. Downloading Tor Browser

The employee downloaded Tor Browser version 15.0.22 and saved the installer to the workstation’s Downloads folder. An installer is a program that places software and supporting files onto a computer so the application can run.

Although Tor Browser is publicly available software, downloading it introduced an unauthorized application into the simulated company environment. This was the first step in the activity sequence later examined through file-event records.

### 2. Installing Tor Silently

The employee launched the installer from an elevated Command Prompt using the `/S` argument. An elevated Command Prompt runs with administrator privileges, while `/S` tells this installer to run without the usual interactive setup screens.

A silent installation can reduce what appears on the screen, but it does not make the activity invisible to security monitoring. The installer’s execution and the files it created provided evidence for the subsequent investigation.

![Tor Browser installer and silent installation command](images/01-silent-install-command.png)

### 3. Launching Tor Browser

After installation, the employee opened Tor Browser from the desktop folder and connected to the Tor network.

Tor Browser uses a browser component based on Firefox and a Tor component that handles communication through the network. The browser passes its traffic to the local Tor proxy, which forwards it through Tor. This explains why the investigation later identified both `firefox.exe` and `tor.exe`.

Tor’s privacy features do not prevent endpoint security software from recording activity on the computer itself. The investigation could examine program execution and connections even though those records did not reveal every page viewed.

![Tor Browser landing page](images/02-tor-connected.png)

### 4. Browsing Dark Web Content

Once connected, the employee visited the Dread forum’s DarkNetMarkets section and viewed a page advertising illicit substances and prices.

The term **dark web** refers to services deliberately hosted on networks requiring specialized software or configurations to access. Tor’s `.onion` services are one example. The dark web includes both legitimate services and illicit content; the content shown in this scenario added context to the misuse of corporate equipment.

Within the simulation, the unauthorized Tor usage violated company policy. The browsing screenshots documented the pages displayed, while the threat hunt separately examined what the workstation’s security records could establish.

![Dread DarkNetMarkets section](images/03-darknet-markets.png)

![Page displaying illicit substance listings](images/04-market-listings.png)

### 5. Creating a Local Shopping List

The employee created `tor-shopping-list.txt` on the desktop and recorded fictional shopping entries based on the displayed content.

This file became an additional piece of evidence, often called an **artifact**: a file or record that helps reconstruct activity during an investigation. Its location, creation time, associated account, and contents gave the analyst information to compare with the browser and network events.

The shopping list was created solely for the lab exercise. Its contents did not establish that a purchase or payment occurred.

![Simulated shopping list on the desktop](images/05-shopping-list.png)

## Threat Hunt: Investigation and Findings

### Hunt Hypothesis and Scope

The working hypothesis was that an employee had installed and used Tor Browser on a company workstation, leaving related file, process, and network evidence.

The investigation focused on:

| Item | Scope |
|---|---|
| Workstation | `shad-th1-onion` |
| Lab account | `shad-wbf757` |
| Telemetry | `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents` |
| Evidence collection | Microsoft Defender Live Response |

The workstation and account names are intentional lab identifiers. Times below reflect the timestamps displayed in the investigation screenshots.

### 1. Identifying the Tor Browser Download

The investigation began with a KQL query against `DeviceFileEvents`, a table containing records of file activity on the workstation. Searching for filenames containing “tor” helped identify potential Tor-related downloads and files for closer review.

```kusto
DeviceFileEvents
| where DeviceName == "shad-th1-onion"
| where FileName contains "tor"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          Account = InitiatingProcessAccountName, InitiatingProcessFileName,
          FileOriginReferrerUrl, FileOriginUrl
```

At **1:26:46 PM**, the results showed a `FileRenamed` event for `tor-browser-windows-x86_64-portable-15.0.22.exe` in the employee’s Downloads folder. A `FileRenamed` event records a change to a file’s name; by itself, it does not prove that a download occurred. However, this record also identified `msedge.exe`—Microsoft Edge—as the initiating process and referenced Tor Project infrastructure in the download origin fields.

Those details provided supporting context: **what the file was called, where it was saved, which application handled it, and where it came from**. Together, they supported the finding that the Tor Browser installer had been downloaded through Microsoft Edge.

The same search also returned files associated with the later installation and a text file named `tor-shopping-list.txt`. These became leads for the next stages of the investigation.

![File events identifying the installer and related artifacts](images/06-installer-download-evidence.png)

### 2. Confirming Silent Installation

The next step was to determine whether the downloaded installer had actually been run. The investigation examined `DeviceProcessEvents`, which records program execution and related details, including the account involved and the command used to start the program.

```kusto
DeviceProcessEvents
| where DeviceName == "shad-th1-onion"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.22.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName,
          FolderPath, SHA256, ProcessCommandLine
| order by Timestamp asc
```

At **1:35:03 PM**, a `ProcessCreated` event showed the Tor installer executing under `shad-wbf757`. A process is a running instance of a program, so this event established that the installer had started.

The command line included the `/S` argument, instructing this installer to run silently. A silent installation runs without the usual interactive setup screens. It can still generate security logs, as the recorded process event demonstrates.

File events around **1:35:12–1:35:16 PM** then showed Tor components and a browser shortcut being created in the desktop’s Tor Browser folder. This provided evidence of what the installer did after starting.

**The execution record showed the installer running, while the subsequent file records showed it placing the browser’s components on the workstation.** Together, they supported the silent installation finding.

![Process event showing silent installer execution](images/07-silent-install-evidence.png)

### 3. Confirming Tor Browser Execution

After establishing installation, the investigation checked whether the employee opened the browser. A follow-up query searched process command lines for `tor.exe` or `firefox.exe`.

```kusto
DeviceProcessEvents
| where DeviceName == "shad-th1-onion"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          SHA256, ProcessCommandLine
| order by Timestamp asc
```

The results showed both programs executing under the employee’s account around **1:36 PM**. In this installation, `firefox.exe` was the browser component, while `tor.exe` handled communication through the Tor network.

The file paths were particularly useful. They placed both programs inside the desktop’s **Tor Browser directory**, connecting them to the installation identified earlier. A filename such as `firefox.exe` alone would provide less context because it could also belong to a separate Firefox installation.

These records supported the finding that **the installed Tor Browser had been launched**. The next step was to determine whether it established network connections.

![Process events showing Tor Browser execution](images/08-browser-process-evidence.png)

### 4. Examining Network Activity

The investigation queried `DeviceNetworkEvents` for connections initiated by `tor.exe` and `firefox.exe` under the employee’s account. This table provides information about network activity, including the program involved, the destination address, the destination port, and whether a connection succeeded.

```kusto
DeviceNetworkEvents
| where DeviceName == "shad-th1-onion"
| where InitiatingProcessAccountName == "shad-wbf757"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
          RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp asc
```

The results showed successful external connections from `tor.exe` beginning at **1:37:09 PM**, over ports **9001** and **443**.

An **IP address** identifies a network destination, while a **port** helps direct a connection to a particular service at that destination. Port **9001** is commonly used by Tor relays to accept connections. Port **443**, commonly associated with HTTPS, can also carry Tor connections. Neither port identifies Tor usage by itself; here, the connections were associated with `tor.exe` and supported by the earlier installation and execution evidence.

Firefox initially failed to connect to **127.0.0.1:9150**, then successfully connected within the same minute. The address **127.0.0.1** refers to the workstation itself. This means the browser was communicating with another component on the same computer.

Port **9150** was the connection point for Tor Browser’s local SOCKS proxy. The proxy acts as a middleman: **the browser sends traffic to the proxy, and the Tor process forwards that traffic through the Tor network**.

Together, the successful browser-to-proxy connection and external connections from `tor.exe` supported active Tor usage. These records showed how the programs communicated, but **they did not establish which onion sites or pages the employee visited**.

![Network events showing local proxy communication and external connections](images/09-network-events.png)

### 5. Locating the Shopping List

The initial file search identified `tor-shopping-list.txt`. A more targeted query then examined where the file was stored and which account was associated with its activity.

```kusto
DeviceFileEvents
| where DeviceName == "shad-th1-onion"
| where FileName contains "tor-shopping-list.txt"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath
| order by Timestamp asc
```

The results placed the file at:

`C:\Users\shad-wbf757\Desktop\tor-shopping-list.txt`

This path identifies a text file on the desktop within the `shad-wbf757` user profile. Establishing the exact location made it possible to retrieve the correct file during evidence collection.

The initial query recorded a `FileCreated` event initiated by `notepad.exe` at **2:02:06 PM**. This indicated that Notepad created the file after the observed Tor Browser execution and network activity.

The account, location, and timing connected the file to the investigation. However, **the filename and creation event did not reveal its contents**. Reviewing the actual file was necessary to determine its relevance.

![File events identifying the shopping list location](images/10-shopping-list-path.png)

### 6. Collecting and Reviewing the File

A Microsoft Defender Live Response session was used to retrieve the file with the `getfile` command. Live Response allows an analyst to connect remotely to a managed workstation and perform investigative actions, such as collecting a file for examination.

```text
getfile C:\Users\shad-wbf757\Desktop\tor-shopping-list.txt
```

Using the path identified in the previous step, the analyst retrieved a copy of `tor-shopping-list.txt` and reviewed its contents. The file contained fictional shopping entries referencing illicit substances, quantities, and prices.

This added context beyond the event logs. The logs established that the file existed and when it was created; examining the file revealed what had been recorded inside it.

Within the simulation, the contents supported the investigation into inappropriate use of company equipment. **They did not establish that a purchase, payment, or transaction occurred.** The retrieval shown below was an analyst’s evidence-collection action during the investigation.

![Live Response collection and review of the shopping list](images/11-live-response-collection.png)

## Reconstructed Timeline

The timeline brings evidence from different sources into one sequence. This helps explain how the activity progressed from downloading the installer to running Tor and creating the text file.

| Time — September 13, 2026 | Evidence and meaning |
|---|---|
| **1:26:46 PM** | A file event linked the Tor installer in Downloads to Microsoft Edge and Tor Project download infrastructure. |
| **1:35:03 PM** | The installer started with `/S`, indicating a silent installation. |
| **1:35:12–1:35:16 PM** | Tor components and a shortcut were created, supporting that installation took place. |
| **Approximately 1:36 PM** | Browser and Tor processes executed from the desktop’s Tor Browser directory. |
| **1:37:09 PM onward** | `tor.exe` successfully connected to external addresses. |
| **1:37:46 PM** | Firefox successfully connected to `127.0.0.1:9150`, the local proxy used to pass browser traffic to Tor. |
| **2:02:06 PM** | Notepad created `tor-shopping-list.txt` on the employee’s desktop. |

## Summary and Recommended Next Steps

The investigation combined file, process, and network telemetry—security records describing activity on the workstation—to reconstruct Tor Browser download, silent installation, execution, and network communication on `shad-th1-onion`. Microsoft Defender Live Response was then used to retrieve and review a related text file.

Each evidence source answered a different question: file records showed what appeared on the workstation, process records showed which programs ran, and network records showed the connections those programs made. Reviewing the collected text file provided additional context about the simulated employee’s activity.

Under the scenario’s policy prohibiting Tor installation and use, these findings supported an acceptable use policy violation. The scenario screenshots documented the browsing content, while the security logs independently supported installation and usage. The evidence presented did not establish a completed purchase, data exfiltration—the unauthorized transfer of company information—or malware compromise.

The following are **recommended next steps**, rather than actions demonstrated in this investigation:

1. **Preserve the evidence.** Retain the event exports, screenshots, and collected file, documenting when and how each was obtained. Calculate a hash—a digital fingerprint—of the collected file to help verify that the retained copy remains unchanged.

2. **Escalate the findings.** Provide security management and the designated HR or employee-relations team with a factual report connecting the observed activity to the applicable company policy.

3. **Confirm attribution and context.** Verify who was using the workstation and whether an approved exception existed. An account name identifies the account involved; additional context helps establish who performed the actions.

4. **Address the unauthorized software.** After preserving evidence, remove Tor Browser through the approved process and apply controls to prevent recurrence. Further containment would depend on whether additional investigation identified an active security threat.

5. **Support the employee review.** HR and management would obtain the employee’s explanation and determine appropriate action under company policy. The security analyst would provide the technical evidence and explain its limitations.

6. **Improve monitoring.** Develop and validate detections using the observed installation, execution, and connection patterns to help identify similar unauthorized activity in the future.

## Disclaimer

This project was completed in a controlled lab for educational and portfolio purposes. No real employee, purchase, or criminal transaction was involved.