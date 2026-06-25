# Splunk Web Server Security Analysis

## Project Overview

This project demonstrates SOC-analyst-level log analysis using Splunk Enterprise. I ingested over 109,000 web server events from a simulated e-commerce environment and used SPL (Search Processing Language) to detect suspicious activity, identify threat actors, and build a security monitoring dashboard.

**Tools Used:** Splunk Enterprise (Free License), SPL  
**Dataset:** Splunk Tutorial Data — simulated web server logs (~109,864 events)  
**Skills Demonstrated:** Log ingestion, SPL querying, threat hunting, anomaly detection, dashboard creation

---

## Dashboard

The dashboard consists of 5 panels:
- HTTP Status Code Distribution (Bar Chart)
- Top 10 IP Addresses by Request Volume (Bar Chart)
- Traffic Volume Over Time (Line Chart)
- HTTP Methods Distribution (Pie Chart)
- Top IPs Causing 404 Errors (Table)

---

## SPL Queries & Findings

### Finding 1 — Suspicious File Download Attempt

```spl
index=main clientip="87.194.216.51" | table _time uri status
```

IP `87.194.216.51` was found probing `/rush/signals.zip?JSESSIONID=SD7SL9FF3ADFF33408` — a non-standard directory path with a session token embedded in the URL. This is indicative of reconnaissance or session hijacking behavior. Normal users do not request `.zip` files directly from web server paths.

---

### Finding 2 — Top Attacker by Request Volume

```spl
index=main | stats count by clientip | sort -count | head 10
```

`87.194.216.51` generated approximately 1,050 total requests — nearly double the next most active IP (`211.166.11.101` with ~735 requests). This volume combined with error patterns strongly suggests automated scanning.

---

### Finding 3 — HTTP Method Analysis

```spl
index=main | stats count by method | sort -count
```

Only GET and POST methods were observed — no anomalous methods such as DELETE, PUT, or OPTIONS that would indicate API abuse or server probing via unusual HTTP verbs.

---

### Finding 4 — Peak Traffic Time Identification

```spl
index=main | timechart count span=1h
```

Traffic showed recurring spikes peaking at approximately 5,000–6,500 events per hour occurring consistently around midnight across multiple days (June 17–23, 2026). Regular midnight spikes suggest **automated/scheduled attack activity** rather than human browsing behavior, which typically follows daytime patterns.

---

### Finding 5 — Top URIs Analysis

```spl
index=main | stats count by uri | sort -count | head 10
```

Top accessed URIs were standard e-commerce pages (`/cart/success.do`, `/category.screen`, `/cart.do`) — consistent with normal shopping behavior. This confirmed the main application was functioning normally while suspicious activity was isolated to specific IPs.

---

### Finding 6 — Abnormal HTTP Error Distribution

```spl
index=main | stats count by status | sort -count
```

| Status Code | Count | Meaning |
|---|---|---|
| 200 | 34,282 | Success (normal) |
| 503 | 952 | Service Unavailable — possible DoS activity |
| 408 | 756 | Request Timeout — possible slow loris attack |
| 500 | 733 | Internal Server Error — possible injection attempts |
| 406 | 710 | Not Acceptable |
| 400 | 701 | Bad Request — malformed/automated requests |
| 404 | 690 | Not Found — page scanning activity |
| 403 | 228 | Forbidden — unauthorized access attempts |

The high volume of 503, 500, and 408 errors collectively suggests automated scanning, potential DoS activity, and possible injection attempts against the application.

---

### Finding 7 — Persistent Threat Actor Identified

```spl
index=main status=200 | stats count by clientip | sort -count | head 10
```

`87.194.216.51` appeared as the top IP across all metrics — 404 errors, successful requests, and total request volume. This pattern of persistence across multiple query types confirms coordinated automated reconnaissance rather than coincidental traffic.

---

### Finding 8 — Response Size Analysis

```spl
index=main | stats avg(bytes) by clientip | sort -avg(bytes) | head 10
```

Average response sizes across all IPs were within the normal range (~2,000 bytes), ruling out large-scale data exfiltration via file downloads. No IP showed anomalously large average byte transfers.

---

### Finding 9 — User Agent Analysis

```spl
index=main | stats count by useragent | sort -count | head 10
```

All top user agents were legitimate browsers — Firefox 3.6, Chrome 19, Internet Explorer 7/9, and Safari on iPad. No known attack tools (sqlmap, nikto, curl, python-requests) were detected via user agent strings. This suggests the threat actor either used a legitimate browser or **spoofed their user agent** to avoid detection — a common evasion technique used by sophisticated attackers.

---

### Finding 10 — Attacker Geolocation

```spl
index=main clientip="87.194.216.51" | iplocation clientip | table clientip City Country
```

Primary threat actor IP `87.194.216.51` was geolocated to **Slough, United Kingdom**. In a production SOC environment, this IP would be cross-referenced against threat intelligence platforms such as VirusTotal and AbuseIPDB to determine if it is a known malicious actor or a compromised endpoint.

---

## Summary of Findings

| # | Finding | Severity |
|---|---|---|
| 1 | Suspicious file download attempt via `/rush/signals.zip` | High |
| 2 | Single IP generating 1,050+ requests — automated scanning | High |
| 3 | Only GET/POST methods observed — no HTTP verb abuse | Low |
| 4 | Recurring midnight traffic spikes — scheduled attack activity | Medium |
| 5 | Top URIs show normal shopping behavior | Informational |
| 6 | 952 x 503, 733 x 500, 756 x 408 errors — DoS/injection indicators | High |
| 7 | Same IP dominant across all metrics — persistent threat actor | High |
| 8 | Average response size ~2,000 bytes — no exfiltration detected | Low |
| 9 | No malicious user agents — possible user agent spoofing | Medium |
| 10 | Attacker geolocated to Slough, United Kingdom | Informational |

---

## Key Takeaways

- A single IP (`87.194.216.51`) was responsible for the majority of suspicious activity across the dataset
- Recurring midnight traffic spikes indicate scheduled/automated attack tools
- The absence of malicious user agents does not confirm absence of attack — sophisticated actors spoof browser strings
- High 500 and 503 error rates suggest the server was under stress from aggressive scanning
- Geolocation and cross-referencing with threat intel databases would be the next step in a real SOC investigation

---

## How to Reproduce

1. Install Splunk Enterprise (Free License) from splunk.com
2. Download the Splunk tutorial dataset (`tutorialdata.zip`)
3. Ingest via Settings → Add Data → Upload
4. Run the SPL queries listed above in Search & Reporting
5. Build dashboard panels using the visualization types specified

---

*Project completed as part of cybersecurity portfolio development. Tools: Splunk Enterprise Free, SPL.*
