# Analisi Sovrapposizione Logging: Windows Events vs Sysmon

## Panoramica

Questo documento analizza la sovrapposizione tra Windows Security Event Log e Sysmon per ottimizzare lo storage e evitare duplicazioni nel SIEM.

## Tabella Comparativa Dettagliata

### Eventi di Processo

| Attività | Windows Event ID | Sysmon Event ID | Raccomandazione |
|----------|-----------------|-----------------|-----------------|
| Process Creation | 4688 | 1 | **Preferire Sysmon 1** - Include hash, parent process, command line completa |
| Process Termination | 4689 | 5 | **Preferire Sysmon 5** - Più dettagli |

### Eventi di Autenticazione (Solo Windows Event - NON duplicati)

| Attività | Windows Event ID | Sysmon | Note |
|----------|-----------------|--------|------|
| Logon Success | 4624 | ❌ | Solo Windows Event - Critico |
| Logon Failed | 4625 | ❌ | Solo Windows Event - **CRITICO per T1110** |
| Logoff | 4634, 4647 | ❌ | Solo Windows Event |
| Kerberos TGT Request | 4768 | ❌ | Solo Windows Event - **CRITICO per T1558** |
| Kerberos Service Ticket | 4769 | ❌ | Solo Windows Event - **CRITICO per T1558** |
| Kerberos Pre-Auth Failed | 4771 | ❌ | Solo Windows Event - **CRITICO per T1110** |
| NTLM Auth Failed | 4776 | ❌ | Solo Windows Event - **CRITICO per T1110** |
| Special Logon | 4672 | ❌ | Solo Windows Event - **CRITICO per T1078** |
| Explicit Credentials | 4648 | ❌ | Solo Windows Event - **CRITICO per T1078** |

### Eventi di Account Management (Solo Windows Event - NON duplicati)

| Attività | Windows Event ID | Sysmon | Note |
|----------|-----------------|--------|------|
| User Account Created | 4720 | ❌ | Solo Windows - **CRITICO per T1136** |
| User Account Enabled | 4722 | ❌ | Solo Windows - **CRITICO per T1098** |
| Password Reset | 4724 | ❌ | Solo Windows - **CRITICO per T1098** |
| User Added to Global Group | 4728 | ❌ | Solo Windows - **CRITICO per T1098** |
| User Added to Local Group | 4732 | ❌ | Solo Windows - **CRITICO per T1098** |
| User Account Changed | 4738 | ❌ | Solo Windows - **CRITICO per T1098** |
| Computer Account Created | 4741 | ❌ | Solo Windows |

### Eventi di File e Registry

| Attività | Windows Event ID | Sysmon Event ID | Raccomandazione |
|----------|-----------------|-----------------|-----------------|
| File Creation | 4663 (con SACL) | 11 | **Preferire Sysmon 11** - Non richiede SACL, più facile |
| File Deletion | 4663 (con SACL) | 23, 26 | **Preferire Sysmon 23/26** |
| Registry Change | 4657 (con SACL) | 12, 13, 14 | **Preferire Sysmon 12-14** - Non richiede SACL |

### Eventi di Rete

| Attività | Windows Event ID | Sysmon Event ID | Raccomandazione |
|----------|-----------------|-----------------|-----------------|
| Network Connection | 5156 (WFP) | 3 | **Preferire Sysmon 3** - Include processo, hash |
| Share Access | 5140, 5145 | ❌ | Solo Windows Event - Utile per T1021.002 |

### Eventi Esclusivi Sysmon (NO sovrapposizione)

| Sysmon Event ID | Descrizione | Windows Equivalente |
|-----------------|-------------|---------------------|
| 2 | File Creation Time Changed | ❌ |
| 6 | Driver Loaded | ❌ |
| 7 | Image Loaded (DLL) | ❌ |
| 8 | CreateRemoteThread | ❌ |
| 9 | RawAccessRead | ❌ |
| 10 | ProcessAccess | ❌ |
| 15 | FileCreateStreamHash | ❌ |
| 17, 18 | Pipe Created/Connected | ❌ |
| 19, 20, 21 | WMI Event | ❌ |
| 22 | DNS Query | ❌ |
| 25 | Process Tampering | ❌ |

## Raccomandazioni per Evitare Duplicati

### Strategia Consigliata

```
┌─────────────────────────────────────────────────────────────────┐
│                    LOGGING STRATEGY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  WINDOWS SECURITY EVENTS (Non sostituibili):                    │
│  ├── Autenticazione: 4624, 4625, 4648, 4672                     │
│  ├── Kerberos: 4768, 4769, 4771, 4776                           │
│  ├── Account Mgmt: 4720, 4722, 4724, 4728, 4732, 4738           │
│  └── Network Share: 5140, 5145                                  │
│                                                                 │
│  SYSMON (Preferibile - Più ricco di contesto):                  │
│  ├── Process: 1, 5 (invece di 4688, 4689)                       │
│  ├── File: 11, 23, 26 (invece di 4663)                          │
│  ├── Registry: 12, 13, 14 (invece di 4657)                      │
│  ├── Network: 3 (invece di 5156)                                │
│  └── Esclusivi: 2, 6-10, 15, 17-22, 25                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Configurazione Consigliata Windows Audit Policy

Per evitare duplicati con Sysmon, disabilitare:

```powershell
# NON necessari se Sysmon è attivo:
# - Process Creation (4688) -> Sysmon Event 1 è superiore
# - Process Termination (4689) -> Sysmon Event 5 è superiore

# MANTENERE ATTIVI (non duplicati da Sysmon):
# - Logon/Logoff: Success e Failure
# - Account Management: Success e Failure
# - Kerberos: Success e Failure
# - Special Logon: Success
# - File Share: Success e Failure
```

### SIEM Correlation Rules

Quando si usano entrambi, creare regole di correlazione che:

1. **Privilegiano Sysmon** per eventi di processo (più contesto)
2. **Usano Windows Events** per autenticazione e account management
3. **Combinano entrambi** per correlazioni avanzate:
   - Windows 4624 (logon) + Sysmon 1 (process) = sessione completa
   - Windows 4728 (group add) + Sysmon 13 (registry) = persistence detection

## Matrice di Copertura MITRE ATT&CK

| Tecnica MITRE | Windows Events | Sysmon Events | Copertura |
|---------------|----------------|---------------|-----------|
| T1110 Brute Force | 4625, 4771, 4776 | 1 (tool detection) | Complementare |
| T1078 Valid Accounts | 4624, 4648, 4672 | 1, 3 | Complementare |
| T1098 Account Manipulation | 4720-4738 | 1 (cmdline) | Complementare |
| T1136 Create Account | 4720 | 1 (cmdline) | Ridondante |
| T1558 Kerberos Tickets | 4768, 4769, 4771 | 1 (tool detection) | Complementare |
| T1003 Credential Dumping | - | 1, 7, 10 | Solo Sysmon |
| T1055 Process Injection | - | 8, 10 | Solo Sysmon |
| T1547 Persistence | 4657 (con SACL) | 12, 13 | Preferire Sysmon |

## Stima Impatto Storage

| Configurazione | Volume Stimato/giorno | Note |
|----------------|----------------------|------|
| Solo Windows Events | 500 MB - 2 GB | Dipende da audit policy |
| Solo Sysmon | 200 MB - 1 GB | Dipende da configurazione |
| Entrambi (con duplicati) | 1 - 4 GB | Non ottimale |
| Entrambi (ottimizzato) | 600 MB - 2.5 GB | Raccomandato |

## Conclusione

**Non esistono veri duplicati** tra Windows Security Events e Sysmon per le tecniche critiche:
- Gli eventi di autenticazione sono **esclusivamente** Windows Events
- Gli eventi di processo injection sono **esclusivamente** Sysmon
- Per process creation, preferire Sysmon per il maggiore contesto

La strategia ottimale è usare **entrambi in modo complementare**, non esclusivo.
