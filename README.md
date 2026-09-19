# Data Exfiltration 

## Project Overview

This project demonstrates the implementation of a Microsoft Sentinel security visualization focused on outbound data transfer activity using **NTANetAnalytics** flow log data. By parsing, enriching, and aggregating VNet flow telemetry, this project transforms raw network flow data into an interactive **KQL (Kusto Query Language) Workbook**.

The primary objective was to build a geographic visualization that identifies where outbound data is being sent, sized by the volume of bytes leaving the network — surfacing the destinations most likely to represent meaningful data exfiltration activity.

---

## Core Visualization & Scenario Implemented

### 1. Exfil-by-Volume — `NTANetAnalytics`

* **Log Source:** `NTANetAnalytics`
* **Objective:** Maps the external **destination** public IP of VNet flows, sized by **bytes leaving the network** (`bytesOut`), to identify which destinations are receiving the largest volumes of outbound data.
* **Business Value:** Provides analysts with geographic and volume-based context for identifying large outbound transfers — the data-exfiltration signal that endpoint-only telemetry (e.g. MDE tables) cannot surface on its own.

#### Visual Dashboard
### Exfil-by-Volume — NTANetAnalytics

<img width="1496" height="367" alt="Data Exfiltration" src="https://github.com/user-attachments/assets/c5a0ef8a-6d42-4861-82d5-4a962584dac2" />



#### The KQL Query

```kusto
NTANetAnalytics
| where SubType == "FlowLog"
| where isnotempty(DestPublicIps)
| extend Parts = split(DestPublicIps, "|")
| extend PublicIp     = tostring(Parts[0]),
         AllowedFlows = tolong(Parts[3]),
         DeniedFlows  = tolong(Parts[4]),
         BytesIn      = tolong(Parts[5]),
         BytesOut     = tolong(Parts[6])
| where isnotempty(PublicIp)
| where BytesOut > 0
| extend geo = geo_info_from_ip_address(PublicIp)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         City      = tostring(geo.city)
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize BytesOut = sum(BytesOut),
            BytesIn   = sum(BytesIn),
            Sources   = dcount(SrcIp),
            Ports     = make_set(DestPort, 15)
         by PublicIp, Country, City, Latitude, Longitude
| extend MB_Out = round(BytesOut / 1048576.0, 1)
| extend MapLabel = strcat(PublicIp, " (", City, ", ", Country, ") - ", MB_Out, " MB out, ", Sources, " sources")
| project Latitude, Longitude, MapLabel, BytesOut, MB_Out, BytesIn, Sources, Ports, PublicIp, Country, City
| order by BytesOut desc
```

### 📊 Dashboard Analysis & Key Findings

### 🔍 KQL Query Breakdown

* **Parses the Packed Field:** `DestPublicIps` stores multiple values in a single delimited string (`IP|flowStarted|flowEnded|allowedInFlows|deniedInFlows|bytesIn|bytesOut`). The query splits this on `|` and extracts each position into a named field.
* **Filters to External Flow Logs:** Uses `SubType == "FlowLog"` to focus on the externally-meaningful flow records, excluding internal-only subtypes.
* **Isolates Outbound Transfers:** Filters to `BytesOut > 0` so the analysis only includes destinations that actually received data.
* **Enriches Destination IPs:** Uses the native `geo_info_from_ip_address()` function to translate destination IPs into geographic coordinates, country, and city.
* **Aggregates by Destination:** Sums bytes out/in and counts distinct internal source hosts (`Sources`) per destination, so a single bubble represents total exfil-relevant traffic to that IP.

### 🗺️ Map Visualization & Legend Key

* **Destination Bubbles:** Each bubble represents a unique external destination IP that received outbound data.
* **Bubble Size (Volume):** Bubble size is driven by `BytesOut` — larger bubbles indicate destinations that received a higher total volume of outbound data.
* **Source Fan-In:** The `Sources` field shows how many distinct internal hosts sent data to that destination — useful for spotting staging points where multiple hosts funnel data outward.
* **Color Coding:** The map uses a green-to-red heatmap based on total bytes out.

### ⚠️ Key Security Anomalies Detected

* **Dominant Outbound Destination:** In this dataset, a single destination (`146.75.38.172`, Ashburn, United States) accounted for **~15,012 MB (≈14.7 GB) out across 59 sources** — over 130x larger than the next-highest destination (`52.252.75.106` at 113.9 MB out). A destination this disproportionate relative to the rest of the traffic is a strong candidate for investigation, even before considering geography.
* **High Source Fan-In:** Destinations receiving traffic from a large number of distinct internal `Sources` (for example, 39–59 sources funneling into a single external IP) may indicate a shared service, CDN, or — depending on context — a staging point aggregating data from many hosts before it leaves the network.
* **Unusual-Region, Low-Volume Outliers:** Small but non-trivial transfers to destinations outside the organization's normal operating regions (e.g. single-source transfers to less common geographies) are lower-volume but still worth reviewing, since exfiltration is sometimes deliberately kept small to avoid volume-based detection.
* **Port Context:** The `Ports` field shows which destination ports carried the traffic (e.g. 80, 443, or unusual high ports). Traffic to non-standard ports alongside a high-volume transfer adds weight to an exfiltration hypothesis.

> Byte volume and geography are investigative signals rather than standalone proof of malicious activity. Legitimate large transfers (backups, CDN traffic, SaaS sync, software updates) can also produce large `BytesOut` values and should be correlated with expected business traffic before escalation.

---

### 2. Destination Volume Breakdown

* **Log Source:** `NTANetAnalytics`
* **Objective:** Provides a destination-level breakdown of outbound byte volume, in MB/GB/TB, alongside inbound bytes and internal source fan-in.
* **Business Value:** Allows analysts to move from the geographic map to a ranked, sortable table of the destinations moving the most data, so the largest transfers can be triaged first.

#### The KQL Query

```kusto
NTANetAnalytics
| where SubType == "FlowLog"
| where isnotempty(DestPublicIps)
| extend Parts = split(DestPublicIps, "|")
| extend PublicIp = tostring(Parts[0]),
         DeniedFlows = tolong(Parts[4]),
         BytesIn  = tolong(Parts[5]),
         BytesOut = tolong(Parts[6])
| where isnotempty(PublicIp) and BytesOut > 0
| extend geo = geo_info_from_ip_address(PublicIp)
| extend Country = tostring(geo.country),
         City    = tostring(geo.city)
| where isnotempty(City) and isnotempty(Country)
| summarize BytesOut = sum(BytesOut),
            BytesIn   = sum(BytesIn),
            Sources   = dcount(SrcIp),
            Ports     = make_set(DestPort, 15)
         by PublicIp, Country, City
| extend MB_Out = round(BytesOut / 1048576.0, 1)
| project PublicIp, Country, City, BytesOut, MBOut = round(toreal(BytesOut)/1024, 1),
    GBOut = round(toreal(BytesOut)/1024/1024, 1),
    TBOut = round(toreal(BytesOut)/1024/1024/1024, 1), BytesIn, Sources, Ports
| order by BytesOut desc
```

### 📊 Dashboard Analysis & Key Findings

### 🔍 KQL Query Breakdown

* **Reuses the Same Parsing Logic:** Splits the packed `DestPublicIps` field and enriches with geography, consistent with the map query above.
* **Provides Multiple Unit Scales:** Projects `BytesOut` alongside pre-converted `MBOut`, `GBOut`, and `TBOut` fields, so the table is readable regardless of transfer size.
* **Ranks by Volume:** Orders results by `BytesOut` descending, surfacing the largest outbound transfers first.

---

## 🗺️ Destination Analysis

* **Destination IP:** Identifies the external address that received the outbound data.
* **Outbound Volume:** `BytesOut` / `MBOut` / `GBOut` / `TBOut` represent the total data sent to that destination, at whichever scale is most readable.
* **Inbound Comparison:** `BytesIn` allows analysts to compare data received from a destination against data sent to it — a heavily outbound-skewed ratio is more consistent with exfiltration than a balanced, two-way conversation.
* **Source Fan-In:** `Sources` identifies how many distinct internal hosts contributed to the total volume sent to that destination.
* **Ports Used:** `Ports` lists the destination ports involved, helping distinguish standard web traffic (80/443) from traffic on unusual ports.

---

## ⚠️ Key Security Anomalies Detected

* **Single Destination Dominating Total Egress:** A destination responsible for a disproportionate share of total outbound volume compared to all other destinations combined is the clearest signal in this dataset and should be the first line investigated.
* **High Fan-In, Moderate Volume:** Destinations with a large number of contributing sources but comparatively modest total volume may indicate a shared or automated service rather than a single compromised host — still worth confirming against known-good infrastructure.
* **Asymmetric In/Out Ratios:** Destinations where `BytesOut` significantly exceeds `BytesIn` are more consistent with data leaving the network than with normal bidirectional application traffic.

---

**NOTE:** The source data for this visualization uses the `NTANetAnalytics` table, which required parsing a packed, delimited field (`DestPublicIps`) rather than working with pre-separated columns. This demonstrates how SIEM queries must be adapted to the structure and capabilities of each log source — in this case, extracting byte-level volume metrics that are not directly available in endpoint-based logon or sign-in tables.

---

## Technical Architecture & Workflow

1. **Ingestion:** Network flow telemetry is collected in **Microsoft Sentinel / Log Analytics** through the `NTANetAnalytics` data source.
2. **Data Extraction:** Used **Kusto Query Language (KQL)** to parse the packed `DestPublicIps` field, filter to outbound flow log traffic, enrich destination IPs with geographic information, and aggregate outbound byte volume.
3. **Visualization:** Configured a **Microsoft Sentinel Workbook** using geographic map and table visualizations to transform raw flow log telemetry into an analyst-friendly data exfiltration dashboard.

---

## Skills Demonstrated

* **Microsoft Sentinel:** Building and configuring security workbooks and visualizations.
* **KQL & Data Analysis:** Parsing packed/delimited fields, filtering, aggregating, and transforming network flow telemetry.
* **Security Data Enrichment:** Using `geo_info_from_ip_address()` to add geographic context to destination IP addresses.
* **Threat Hunting & Investigation:** Identifying disproportionate outbound transfers and high source fan-in as data exfiltration indicators.
* **Data Visualization:** Translating raw flow log telemetry into geographic and destination-level security dashboards.
