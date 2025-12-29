# Sysmon Enterprise Security Monitoring - Guida Tecnica Completa

**Versione:** 2.1.0
**Data:** 29 Dicembre 2025
**Classificazione:** Uso Interno
**Autore:** Security Engineering Team

---

## Indice

1. [Sommario Esecutivo](#1-sommario-esecutivo)
2. [Panoramica del Progetto](#2-panoramica-del-progetto)
3. [Architettura e Approccio Progettuale](#3-architettura-e-approccio-progettuale)
4. [Configurazioni per Ruolo](#4-configurazioni-per-ruolo)
5. [Rilevamento Minacce e Copertura MITRE ATT&CK](#5-rilevamento-minacce-e-copertura-mitre-attck)
6. [Integrazione Windows Security Events](#6-integrazione-windows-security-events)
7. [Script di Deployment](#7-script-di-deployment)
8. [Framework di Testing](#8-framework-di-testing)
9. [Integrazione SIEM](#9-integrazione-siem)
10. [Valutazione Production Readiness](#10-valutazione-production-readiness)
11. [Appendici](#11-appendici)

---

## 1. Sommario Esecutivo

### 1.1 Scopo

Questo documento fornisce una guida tecnica completa per il deployment e la gestione del monitoraggio di sicurezza basato su Sysmon attraverso l'infrastruttura Windows aziendale. Consolida tutta la documentazione del progetto in un unico riferimento autorevole.

### 1.2 Risultati Chiave

| Metrica | Valore | Stato |
|---------|--------|-------|
| **Punteggio Production Readiness** | 92/100 | Pronto |
| **Copertura MITRE ATT&CK** | 81-90% | Eccellente |
| **Configurazioni Disponibili** | 6 per ruolo | Completo |
| **Lingue Supportate** | 5 (EN, IT, DE, FR, ES) | Multi-lingua |
| **Integrazione CI/CD** | GitHub Actions | Automatizzato |

### 1.3 Panoramica della Soluzione

```
┌─────────────────────────────────────────────────────────────────────┐
│                MONITORAGGIO SICUREZZA ENTERPRISE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │   Sysmon    │    │   Windows   │    │  PowerShell │            │
│   │   Eventi    │ +  │   Security  │ +  │   Logging   │ = 95%+     │
│   │   (1-26)    │    │   Eventi    │    │ (4103/4104) │  Copertura │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────┐     │
│   │                      SPLUNK SIEM                          │     │
│   │   - Correlazione real-time                                │     │
│   │   - Threat hunting                                        │     │
│   │   - Incident response                                     │     │
│   └──────────────────────────────────────────────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 Quick Start

```powershell
# 1. Installa Sysmon con configurazione workstation
sysmon.exe -accepteula -i sysmon-ws.xml

# 2. Configura Windows Audit Policy (supporto multi-lingua)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cereZ23/sysmon/main/sysmon/deploy/windows-audit-policy.ps1" -OutFile "audit-policy.ps1"
powershell.exe -ExecutionPolicy Bypass -File .\audit-policy.ps1

# 3. Abilita PowerShell logging
powershell.exe -ExecutionPolicy Bypass -File .\enable-powershell-logging.ps1
```

---

## 2. Panoramica del Progetto

### 2.1 Obiettivi

1. **Rilevamento Minacce Completo** - Coprire 40+ tecniche MITRE ATT&CK
2. **Ottimizzazione per Ruolo** - Configurazioni specifiche per ogni tipo di sistema
3. **Riduzione del Rumore** - 60-70% riduzione volume eventi su workstation
4. **Supporto Multi-Lingua** - Funziona su tutte le versioni linguistiche di Windows
5. **Pronto per la Produzione** - Testato e validato per deployment enterprise

### 2.2 Struttura del Progetto

```
sysmon-repo/
├── README.md                          # Panoramica principale
├── sysmon/
│   ├── sysmon-ws.xml                  # Configurazione Workstation
│   ├── sysmon-srv.xml                 # Configurazione Server Generico
│   ├── sysmon-dc.xml                  # Configurazione Domain Controller
│   ├── sysmon-sql.xml                 # Configurazione SQL Server
│   ├── sysmon-exch.xml                # Configurazione Exchange Server
│   ├── sysmon-iis.xml                 # Configurazione IIS Web Server
│   │
│   ├── deploy/                        # Script di deployment
│   │   ├── windows-audit-policy.ps1   # Windows Audit Policy (v2.1.0)
│   │   ├── enable-powershell-logging.ps1
│   │   └── README.md
│   │
│   ├── tests/                         # Framework di testing
│   │   ├── Test-SysmonDetection.ps1   # Validazione rapida
│   │   ├── Run-AtomicTests.ps1        # Atomic Red Team
│   │   └── README.md
│   │
│   ├── docs/                          # Documentazione tecnica
│   │   └── WINDOWS-EVENT-RAW-DATA-REFERENCE.md
│   │
│   └── manuali/                       # Manuali in italiano
│       └── MANUALE-*.md
│
└── .github/workflows/
    └── sysmon-test.yml                # Automazione CI/CD
```

### 2.3 Requisiti

| Componente | Versione Minima | Raccomandata |
|------------|-----------------|--------------|
| Sysmon | v15.0 | v15.15+ |
| Schema Version | 4.50 | 4.90 |
| Windows Workstation | Windows 10 | Windows 11 |
| Windows Server | Server 2016 | Server 2022 |
| PowerShell | 5.1 | 7.x |

---

## 3. Architettura e Approccio Progettuale

### 3.1 Strategia Defense-in-Depth

La soluzione implementa un'**architettura di logging a tre livelli**:

```
Livello 1: Sysmon (Attivita Processo e Sistema)
           ├── Creazione/Terminazione Processo (Evento 1, 5)
           ├── Connessioni di Rete (Evento 3)
           ├── Operazioni File (Evento 11, 23, 26)
           ├── Modifiche Registry (Evento 12, 13, 14)
           ├── Caricamento DLL (Evento 7)
           ├── Process Injection (Evento 8, 10)
           └── Eventi WMI (Evento 19, 20, 21)

Livello 2: Windows Security Events (Autenticazione e Autorizzazione)
           ├── Logon/Logoff (Evento 4624, 4625, 4634)
           ├── Gestione Account (Evento 4720-4738)
           ├── Uso Privilegi (Evento 4672, 4673)
           ├── Accesso Oggetti (Evento 4656, 4663)
           └── Modifiche Policy (Evento 4719, 4739)

Livello 3: PowerShell Logging (Esecuzione Script)
           ├── Module Logging (Evento 4103)
           └── Script Block Logging (Evento 4104)
```

### 3.2 Filosofia di Configurazione per Ruolo

| Tipo Sistema | Postura Monitoraggio | Tolleranza Rumore | Focus Principale |
|--------------|---------------------|-------------------|------------------|
| **Workstation** | Bilanciata | Bassa | Attivita utente, phishing, LOLBins |
| **Server Generico** | Aggressiva | Media | Movimento laterale, persistenza |
| **Domain Controller** | Massima | Alta | Attacchi AD, furto credenziali |
| **SQL Server** | Focus database | Media | SQL injection, xp_cmdshell |
| **Exchange Server** | Focus email | Media | Webshell, ProxyLogon |
| **IIS Web Server** | Focus web | Media | RCE, web shell, C2 |

### 3.3 Matrice Copertura Event ID

| Event ID | Nome | WS | SRV | DC | SQL | EXCH | IIS |
|----------|------|:--:|:---:|:--:|:---:|:----:|:---:|
| 1 | ProcessCreate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 | FileCreateTime | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3 | NetworkConnect | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5 | ProcessTerminate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6 | DriverLoad | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7 | ImageLoad | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 8 | CreateRemoteThread | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 9 | RawAccessRead | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 10 | ProcessAccess | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 11 | FileCreate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 12 | RegistryAddDelete | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 13 | RegistryValueSet | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 14 | RegistryRename | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 15 | FileCreateStreamHash | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 17 | PipeCreated | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 18 | PipeConnected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 19 | WmiFilter | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 20 | WmiConsumer | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 21 | WmiBinding | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 22 | DnsQuery | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 23 | FileDelete | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 25 | ProcessTampering | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 26 | FileDeleteDetected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## 4. Configurazioni per Ruolo

### 4.1 Workstation (sysmon-ws.xml)

**Target:** Endpoint client Windows 10/11
**Dimensione:** 56.5 KB
**Riduzione Rumore:** 60-70%

**Rilevamenti Chiave:**
- Esecuzione macro Office → cmd/powershell
- Esecuzione payload phishing
- Credential dumping (accesso LSASS)
- Abuso LOLBins (certutil, mshta, ecc.)
- Attacchi browser-based

**Esclusioni Applicate:**
- Attivita browser Chrome, Edge, Firefox
- Processi background Microsoft Teams
- Operazioni sync OneDrive
- Windows Update/Search Indexer

**Installazione:**
```powershell
sysmon.exe -accepteula -i sysmon-ws.xml
```

### 4.2 Server Generico (sysmon-srv.xml)

**Target:** Windows Server 2016/2019/2022
**Dimensione:** 45.2 KB
**Postura Monitoraggio:** Aggressiva

**Rilevamenti Chiave:**
- Movimento laterale via PsExec, WMI
- Meccanismi di persistenza (servizi, task)
- Comandi discovery (net, nltest)
- Uso sospetto client RDP

**Installazione:**
```powershell
sysmon.exe -accepteula -i sysmon-srv.xml
```

### 4.3 Domain Controller (sysmon-dc.xml)

**Target:** Active Directory Domain Services
**Dimensione:** 25.1 KB
**Postura Monitoraggio:** Massima (Asset Tier-0)

**Rilevamenti Chiave:**
- Attacchi DCSync (DRSUAPI)
- Creazione Golden Ticket
- Kerberoasting
- Ricognizione AD (ADFind, BloodHound)
- Malware Skeleton Key
- Abuso ntdsutil.exe

**Named Pipe Critiche Monitorate:**
```
\\.\pipe\drsuapi
\\.\pipe\samr
\\.\pipe\lsarpc
\\.\pipe\netlogon
```

**Installazione:**
```powershell
sysmon.exe -accepteula -i sysmon-dc.xml
```

### 4.4 SQL Server (sysmon-sql.xml)

**Target:** SQL Server 2016/2019/2022
**Dimensione:** 38.7 KB

**Rilevamenti Chiave:**
- Esecuzione xp_cmdshell
- SQL injection → comando OS
- Esfiltrazione backup database
- sqlservr.exe che genera cmd/powershell
- Esecuzione stored procedure sospette

**Installazione:**
```powershell
sysmon.exe -accepteula -i sysmon-sql.xml
```

### 4.5 Exchange Server (sysmon-exch.xml)

**Target:** Exchange Server 2016/2019
**Dimensione:** 24.3 KB

**Rilevamenti Chiave:**
- Sfruttamento ProxyLogon/ProxyShell
- Deployment webshell
- Catene w3wp.exe → cmd/powershell
- Attivita raccolta email
- Attivita OWA sospetta

**Installazione:**
```powershell
sysmon.exe -accepteula -i sysmon-exch.xml
```

### 4.6 IIS Web Server (sysmon-iis.xml)

**Target:** Server Web IIS
**Dimensione:** 29.8 KB

**Rilevamenti Chiave:**
- Esecuzione webshell
- RCE via w3wp.exe
- Creazione file aspx/php sospetti
- Pattern comunicazione C2
- Tentativi directory traversal

**Installazione:**
```powershell
sysmon.exe -accepteula -i sysmon-iis.xml
```

---

## 5. Rilevamento Minacce e Copertura MITRE ATT&CK

### 5.1 Copertura per Tattica

| Tattica | Tecniche Coperte | Tasso Rilevamento |
|---------|------------------|-------------------|
| **Execution** | T1059, T1047, T1106, T1204 | 90%+ |
| **Persistence** | T1547, T1053, T1543, T1546, T1136 | 85%+ |
| **Privilege Escalation** | T1548, T1134 | 80%+ |
| **Defense Evasion** | T1218, T1027, T1070, T1562 | 85%+ |
| **Credential Access** | T1003, T1552, T1555 | 90%+ |
| **Discovery** | T1087, T1018, T1082, T1057 | 75%+ |
| **Lateral Movement** | T1021, T1570 | 85%+ |
| **Collection** | T1114, T1056, T1560 | 80%+ |
| **Command & Control** | T1071, T1105 | 75%+ |

### 5.2 Tasso di Rilevamento per Configurazione

| Configurazione | Tecniche Testate | Rilevate | Tasso |
|----------------|------------------|----------|-------|
| Workstation (ws) | 40 | 33 | 82.5% |
| Server Generico (srv) | 40 | 35 | 87.5% |
| Domain Controller (dc) | 40 | 36 | 90.0% |
| SQL Server (sql) | 40 | 33 | 82.5% |
| Exchange (exch) | 40 | 32 | 80.0% |
| IIS (iis) | 40 | 29 | 72.5% |

### 5.3 Rilevamento Tecniche Critiche

#### T1003.001 - Credential Dumping da Memoria LSASS

**Metodo di Rilevamento:** ProcessAccess (Evento 10)
```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
</ProcessAccess>
```

**Query Splunk:**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|wininit)\.exe$")
| table _time, Computer, SourceImage, GrantedAccess
```

#### T1059.001 - Esecuzione PowerShell

**Metodo di Rilevamento:** ProcessCreate (Evento 1) + Script Block Logging (4104)
```xml
<ProcessCreate onmatch="include">
  <CommandLine condition="contains">-enc</CommandLine>
  <CommandLine condition="contains">-encodedcommand</CommandLine>
</ProcessCreate>
```

**Query Splunk:**
```spl
index=sysmon EventCode=1
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, Computer, User, ParentImage, Image, CommandLine
```

#### T1543.003 - Persistenza Windows Service

**Metodo di Rilevamento:** Windows Security Event 4697
```
Evento 4697: Un servizio e stato installato nel sistema
- ServiceName: Nome del servizio malevolo
- ServiceFileName: Path all'eseguibile malevolo
- ServiceType: Tipo di servizio
```

**Query Splunk:**
```spl
index=wineventlog EventCode=4697
| where NOT match(ServiceFileName, "(?i)^C:\\(Windows|Program Files)")
| table _time, Computer, ServiceName, ServiceFileName, SubjectUserName
```

#### T1021.002 - SMB/Windows Admin Shares

**Metodo di Rilevamento:** NetworkConnect (Evento 3) + Named Pipes (Evento 17/18)
```xml
<NetworkConnect onmatch="include">
  <DestinationPort condition="is">445</DestinationPort>
</NetworkConnect>
<PipeEvent onmatch="include">
  <PipeName condition="contains">psexec</PipeName>
</PipeEvent>
```

---

## 6. Integrazione Windows Security Events

### 6.1 Strategia Complementare

Sysmon e Windows Security Events forniscono **copertura complementare**:

| Capacita | Sysmon | Windows Events | Combinato |
|----------|--------|----------------|-----------|
| Creazione Processo | ✓✓✓ (hash, parent) | ✓ (base) | ✓✓✓ |
| Autenticazione | - | ✓✓✓ | ✓✓✓ |
| Gestione Account | - | ✓✓✓ | ✓✓✓ |
| Installazione Servizi | - | ✓✓✓ (Evento 4697) | ✓✓✓ |
| Connessioni di Rete | ✓✓✓ | ✓ (log firewall) | ✓✓✓ |
| Modifiche Registry | ✓✓✓ | ✓ (limitato) | ✓✓✓ |
| PowerShell | ✓ (processo) | ✓✓✓ (contenuto script) | ✓✓✓ |

**Copertura Combinata: 95%+**

### 6.2 Windows Security Events Chiave

| Event ID | Descrizione | MITRE ATT&CK |
|----------|-------------|--------------|
| 4625 | Logon Fallito | T1110 Brute Force |
| 4648 | Credenziali Esplicite | T1078 Valid Accounts |
| 4672 | Privilegi Speciali | T1134 Token Manipulation |
| 4697 | Servizio Installato | T1543.003 Windows Service |
| 4698 | Scheduled Task Creato | T1053.005 Scheduled Task |
| 4720 | Account Utente Creato | T1136.001 Local Account |
| 4722 | Account Utente Abilitato | T1098 Account Manipulation |
| 4724 | Reset Password | T1098 Account Manipulation |
| 4732 | Membro Aggiunto a Gruppo | T1098 Privilege Escalation |

### 6.3 Eventi PowerShell Logging

| Event ID | Log | Descrizione | Valore Detection |
|----------|-----|-------------|------------------|
| 4103 | PowerShell/Operational | Module Logging | Esecuzione pipeline comandi |
| 4104 | PowerShell/Operational | Script Block Logging | Contenuto script completo (critico) |

**Pattern Rilevabili nell'Evento 4104:**
- `-EncodedCommand` (offuscamento Base64)
- `Invoke-Expression` / `IEX` (esecuzione dinamica)
- `DownloadString` / `DownloadFile` (contenuto remoto)
- `FromBase64String` (decodifica payload)
- `Invoke-Mimikatz` (credential dumping)
- `[Reflection.Assembly]::Load` (caricamento in memoria)

---

## 7. Script di Deployment

### 7.1 Script Windows Audit Policy (v2.1.0)

**File:** `sysmon/deploy/windows-audit-policy.ps1`

#### Supporto Multi-Lingua

Lo script usa **GUID invece di nomi localizzati**, garantendo compatibilita con TUTTE le lingue Windows:

| Lingua | Stato | Testato in CI |
|--------|-------|---------------|
| English (en-US) | ✓ Supportato | ✓ |
| Italiano (it-IT) | ✓ Supportato | ✓ |
| Deutsch (de-DE) | ✓ Supportato | ✓ |
| Francais (fr-FR) | ✓ Supportato | ✓ |
| Espanol (es-ES) | ✓ Supportato | ✓ |

**Implementazione Tecnica:**
```powershell
# Prima della v2.1.0 (falliva su Windows non-inglese):
auditpol /set /subcategory:"Logon" /success:enable
# Errore 0x00000057 su Windows italiano

# Dopo la v2.1.0 (funziona su TUTTE le lingue):
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable
```

#### Utilizzo

```powershell
# Configurazione standard
.\windows-audit-policy.ps1

# Con Sysmon installato (salta eventi duplicati)
.\windows-audit-policy.ps1 -SysmonInstalled

# Ripristina policy default
.\windows-audit-policy.ps1 -RestoreDefaults

# Path log personalizzato
.\windows-audit-policy.ps1 -LogPath "D:\Logs\Audit"
```

#### Parametri

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `-LogPath` | `C:\SecurityBaseline\Logs` | Posizione backup e log |
| `-BackupExisting` | `$true` | Crea backup prima delle modifiche |
| `-RestoreDefaults` | `$false` | Ripristina policy Windows default |
| `-SysmonInstalled` | `$false` | Salta Process Creation/Termination |

#### Esempio Output

```
[2025-12-29 15:59:40] [Info] Windows Audit Policy Configuration Script
[2025-12-29 15:59:40] [Info] Version 2.1.0 (Multi-Language Support)
[2025-12-29 15:59:40] [Success] Backup creato con successo
[2025-12-29 15:59:41] [Info] Configurazione: Logon (Success: True, Failure: True)
...
[2025-12-29 15:59:42] [Success] Configurazione Completata
[2025-12-29 15:59:42] [Info] Policy configurate con successo: 55
[2025-12-29 15:59:42] [Info] Policy fallite: 0
```

### 7.2 Script PowerShell Logging (v1.0.0)

**File:** `sysmon/deploy/enable-powershell-logging.ps1`

#### Utilizzo

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\enable-powershell-logging.ps1
```

#### Modifiche Registry Applicate

```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
  EnableModuleLogging = 1
  ModuleNames = *

HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging = 1
  EnableScriptBlockInvocationLogging = 1
```

---

## 8. Framework di Testing

### 8.1 Panoramica Strategia di Testing

```
┌─────────────────────────────────────────────────────────────────────┐
│                      STRATEGIA DI TESTING                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────┐    ┌──────────────────┐    ┌───────────────┐ │
│  │ Validazione      │    │  Atomic Red Team │    │  CI/CD        │ │
│  │ Rapida           │    │  (Attacchi Reali)│    │  (Automatico) │ │
│  │ (Simulata)       │    │                   │    │               │ │
│  │                   │    │                   │    │               │ │
│  │  - 5-10 minuti   │    │  - 30-60 minuti  │    │  - Su commit  │ │
│  │  - Nessun        │    │  - Artefatti     │    │  - Tutte le   │ │
│  │    artefatto     │    │    completi      │    │    config     │ │
│  │  - Sicuro        │    │  - Sandbox req.  │    │  - Multi-lang │ │
│  └──────────────────┘    └──────────────────┘    └───────────────┘ │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Validazione Rapida (Test-SysmonDetection.ps1)

**Scopo:** Validazione veloce senza minacce reali
**Durata:** 5-10 minuti
**Sicurezza:** Nessun artefatto malevolo creato

```powershell
# Esegui validazione rapida
.\sysmon\tests\Test-SysmonDetection.ps1 -ConfigType ws -CI

# Tipi config supportati: ws, srv, dc, sql, exch, iis
```

**Tecniche Testate:**
- Creazione processo con argomenti sospetti
- Creazione chiave Registry Run
- Creazione named pipe (pattern C2)
- Query DNS a domini sospetti
- Creazione file in posizioni sensibili

### 8.3 Testing Atomic Red Team (Run-AtomicTests.ps1)

**Scopo:** Testing completo con tecniche di attacco reali
**Durata:** 30-60 minuti
**Requisito:** Ambiente sandbox isolato

```powershell
# Installa Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics -Force

# Esegui test completi
.\sysmon\tests\Run-AtomicTests.ps1 -ConfigType ws
```

**40 Tecniche MITRE ATT&CK Testate:**

| Categoria | Tecniche |
|-----------|----------|
| Execution | T1059.001, T1059.003, T1047, T1106, T1204.002 |
| Persistence | T1547.001, T1053.005, T1543.003, T1546.003, T1136.001 |
| Privilege Escalation | T1548.002, T1134.001 |
| Defense Evasion | T1218.005/010/011, T1027, T1140, T1070.001/004, T1562.001 |
| Credential Access | T1003.001/002/003, T1552.001, T1555.003 |
| Discovery | T1087.001/002, T1082, T1057, T1018, T1016, T1069.002, T1482 |
| Lateral Movement | T1021.002, T1570 |
| Collection | T1560.001, T1005, T1074.001 |
| C2 | T1105, T1071.001 |

### 8.4 Ambienti Sandbox

#### Opzione 1: Windows Sandbox (Raccomandato)

```powershell
# Abilita Windows Sandbox
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM"

# Esegui setup sandbox
.\sysmon\tests\setup-sandbox.ps1
```

**Vantaggi:**
- Eliminabile (stato pulito ad ogni avvio)
- Nessuna persistenza
- Avvio veloce
- Nessuna licenza aggiuntiva

#### Opzione 2: VM Hyper-V

**Vantaggi:**
- Funzionalita Windows complete
- Capacita snapshot/restore
- Isolamento rete
- Ambiente test persistente

#### Opzione 3: GitHub Actions (CI/CD)

**Trigger:** Automatico su modifiche codice
**Ambiente:** Windows Server 2025
**Copertura:** Tutte 6 configurazioni + test multi-lingua

### 8.5 Workflow CI/CD

**File:** `.github/workflows/sysmon-test.yml`

**Job Eseguiti:**

| Job | Trigger | Scopo |
|-----|---------|-------|
| `validate-xml` | Push/PR | Validazione sintassi XML |
| `test-sysmon-configs` | Push/PR | Installa/verifica tutte 6 config |
| `atomic-red-team` | Manuale | Testing Atomic Red Team completo |
| `windows-event-tests` | Manuale | Testing Windows Security Event |
| `multilang-audit-test` | Manuale | Testing audit policy multi-lingua |

**Trigger Manuale:**
```bash
gh workflow run "Sysmon Detection Testing" --field config_type=all
```

---

## 9. Integrazione SIEM

### 9.1 Configurazione Index Splunk

```
[sysmon]
homePath = $SPLUNK_DB/sysmon/db
coldPath = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb

[wineventlog]
homePath = $SPLUNK_DB/wineventlog/db
coldPath = $SPLUNK_DB/wineventlog/colddb
thawedPath = $SPLUNK_DB/wineventlog/thaweddb
```

### 9.2 Query di Rilevamento Chiave

#### Rilevamento PowerShell Encoded
```spl
index=sysmon EventCode=1
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, Computer, User, ParentImage, Image, CommandLine
```

#### Accesso Credenziali LSASS
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|wininit)\.exe$")
| table _time, Computer, SourceImage, GrantedAccess
```

#### Esecuzione Macro Office
```spl
index=sysmon EventCode=1
| search ParentImage IN ("*winword.exe", "*excel.exe", "*powerpnt.exe")
| search Image IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*mshta.exe")
| table _time, Computer, ParentImage, Image, CommandLine
```

#### Named Pipe Cobalt Strike
```spl
index=sysmon EventCode=17 OR EventCode=18
| search PipeName IN ("*msagent_*", "*MSSE-*", "*postex_*", "*meterpreter*")
| table _time, Computer, Image, PipeName
```

#### Burst Comandi Discovery
```spl
index=sysmon EventCode=1
| search Image IN ("*whoami.exe", "*net.exe", "*nltest.exe", "*systeminfo.exe")
| bucket _time span=5m
| stats count by _time, Computer, User
| where count > 5
```

#### Rilevamento Brute Force
```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, IpAddress, LogonType
| where count > 5
| sort -count
```

#### Installazione Servizio (Persistenza)
```spl
index=wineventlog EventCode=4697
| where NOT match(ServiceFileName, "(?i)^C:\\(Windows|Program Files)")
| table _time, Computer, ServiceName, ServiceFileName, SubjectUserName
```

#### Analisi Script Block PowerShell
```spl
index=wineventlog EventCode=4104 LogName="Microsoft-Windows-PowerShell/Operational"
| where match(ScriptBlockText, "(?i)(-enc|downloadstring|invoke-expression|frombase64)")
| table _time, Computer, ScriptBlockId, ScriptBlockText
```

---

## 10. Valutazione Production Readiness

### 10.1 Punteggio Complessivo

**Production Readiness: 92/100**

| Categoria | Punteggio | Peso | Ponderato |
|-----------|-----------|------|-----------|
| Copertura Rilevamento | 97 | 25% | 24.25 |
| Validita Schema/Sintassi | 95 | 15% | 14.25 |
| Ottimizzazione Performance | 90 | 20% | 18.00 |
| Prontezza Deployment | 90 | 15% | 13.50 |
| Qualita Documentazione | 95 | 10% | 9.50 |
| Allineamento Compliance | 95 | 10% | 9.50 |
| Sicurezza Esclusioni | 70 | 5% | 3.50 |
| **TOTALE** | - | 100% | **92.50** |

### 10.2 Valutazione Dettagliata

#### Copertura Rilevamento (97/100)

**Punti di Forza:**
- 13 tecniche MITRE ATT&CK esplicitamente coperte
- Rilevamento credential dumping (procdump, comsvcs.dll, LSASS)
- Monitoraggio LOLBins (certutil, mshta, regsvr32, ecc.)
- Rilevamento persistenza (Run keys, Task, WMI)
- Movimento laterale (PsExec, named pipes)

**Aree di Miglioramento:**
- Rilevamento DLL sideloading potrebbe essere potenziato
- Alcune tecniche si basano su firme specifiche

#### Ottimizzazione Performance (90/100)

**Punti di Forza:**
- 60-70% riduzione eventi su workstation
- Rumore browser filtrato efficacemente
- Esclusioni processi background

**Aree di Miglioramento:**
- Alcune esclusioni potrebbero essere troppo ampie
- Considerare tuning per ambiente specifico

#### Sicurezza Esclusioni (70/100)

**Preoccupazioni Identificate:**
- Alcune esclusioni potrebbero essere sfruttate
- Raccomandare esclusioni path-specific
- Revisione regolare efficacia esclusioni

### 10.3 Checklist Deployment

- [ ] Revisione tutte le esclusioni per il proprio ambiente
- [ ] Test in sandbox prima della produzione
- [ ] Configurazione regole correlazione SIEM
- [ ] Setup alerting per eventi critici
- [ ] Documentazione personalizzazioni locali
- [ ] Definizione cadenza revisione (trimestrale)
- [ ] Training SOC sulle nuove capacita di rilevamento

---

## 11. Appendici

### 11.1 Codici Tipo Logon Windows

| Codice | Tipo | Descrizione |
|--------|------|-------------|
| 2 | Interactive | Logon console |
| 3 | Network | Connessione SMB/IPC$ |
| 4 | Batch | Scheduled task |
| 5 | Service | Avvio servizio |
| 7 | Unlock | Sblocco workstation |
| 8 | NetworkCleartext | IIS basic auth |
| 9 | NewCredentials | RunAs /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Credenziali cached |

### 11.2 Codici Stato Fallimento Logon Windows

| Status | Descrizione |
|--------|-------------|
| 0xc000006d | Username o password errati |
| 0xc0000064 | Utente non esiste |
| 0xc000006a | Password errata |
| 0xc0000234 | Account bloccato |
| 0xc0000072 | Account disabilitato |
| 0xc000006f | Logon fuori orario consentito |
| 0xc0000070 | Workstation non autorizzata |
| 0xc0000193 | Account scaduto |

### 11.3 Codici Tipo Servizio Windows

| Tipo | Descrizione |
|------|-------------|
| 0x1 | Kernel Driver |
| 0x2 | File System Driver |
| 0x10 | Own Process |
| 0x20 | Share Process |
| 0x100 | Interactive |

### 11.4 GUID Subcategorie Audit

```powershell
# Account Logon
"Credential Validation"              = "{0CCE923F-69AE-11D9-BED3-505054503030}"
"Kerberos Authentication Service"    = "{0CCE9242-69AE-11D9-BED3-505054503030}"
"Kerberos Service Ticket Operations" = "{0CCE9240-69AE-11D9-BED3-505054503030}"

# Logon/Logoff
"Logon"                              = "{0CCE9215-69AE-11D9-BED3-505054503030}"
"Logoff"                             = "{0CCE9216-69AE-11D9-BED3-505054503030}"
"Special Logon"                      = "{0CCE921B-69AE-11D9-BED3-505054503030}"

# Account Management
"User Account Management"            = "{0CCE9235-69AE-11D9-BED3-505054503030}"
"Security Group Management"          = "{0CCE9237-69AE-11D9-BED3-505054503030}"

# Policy Change
"Audit Policy Change"                = "{0CCE922F-69AE-11D9-BED3-505054503030}"

# System
"Security System Extension"          = "{0CCE9211-69AE-11D9-BED3-505054503030}"
```

### 11.5 Riferimenti Documenti

| Documento | Posizione | Scopo |
|-----------|-----------|-------|
| README.md | `/` | Panoramica progetto |
| README-{ruolo}.md | `/sysmon/` | Guide per ruolo |
| MITRE-COVERAGE-REPORT.md | `/sysmon/` | Tassi rilevamento |
| WINDOWS-EVENT-RAW-DATA-REFERENCE.md | `/sysmon/docs/` | Esempi eventi |
| Deploy README | `/sysmon/deploy/` | Documentazione script |
| Tests README | `/sysmon/tests/` | Guida testing |

---

## Changelog

### Versione 2.1.0 (Dicembre 2025)

- **Supporto Multi-Lingua:** Script audit policy ora usa GUID
- **Potenziamento CI/CD:** Aggiunto testing multi-locale (IT, DE, FR, ES)
- **Documentazione:** Consolidata tutta la doc in guida unica
- **Testing:** Copertura Atomic Red Team estesa a 40 tecniche

### Versione 2.0.0 (Dicembre 2025)

- **Release Iniziale:** 6 configurazioni per ruolo
- **Windows Events:** Aggiunto monitoraggio eventi sicurezza complementare
- **PowerShell Logging:** Abilitato Script Block e Module logging
- **Integrazione Splunk:** Query di esempio e configurazione index

---

**Classificazione Documento:** Uso Interno
**Ultimo Aggiornamento:** 29 Dicembre 2025
**Prossima Revisione:** Marzo 2026
**Autore:** Security Engineering Team

---

*Questo documento consolida tutta la documentazione del progetto. Per informazioni dettagliate su argomenti specifici, fare riferimento ai singoli documenti elencati nell'Appendice 11.5.*
