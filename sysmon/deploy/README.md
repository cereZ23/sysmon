# Windows Security Logging Deploy Scripts

Script per la configurazione del logging di sicurezza su Windows.

## Script Disponibili

| Script | Versione | Descrizione |
|--------|----------|-------------|
| `windows-audit-policy.ps1` | 2.1.0 | Configura Windows Advanced Audit Policy |
| `enable-powershell-logging.ps1` | 1.0.0 | Abilita PowerShell Script Block e Module Logging |

---

## windows-audit-policy.ps1

### Panoramica

Configura 55+ subcategorie di audit Windows per il logging completo degli eventi di sicurezza.

### Compatibilita Multi-Lingua

**Versione 2.1.0** - Supporta TUTTE le lingue Windows:
- Italiano (it-IT)
- English (en-US)
- Deutsch (de-DE)
- Francais (fr-FR)
- Espanol (es-ES)
- E tutte le altre...

Il script usa **GUID** invece dei nomi delle subcategorie, che sono localizzati in base alla lingua del sistema.

```powershell
# Prima (falliva su Windows non-inglese con errore 0x00000057):
auditpol /set /subcategory:"Logon" /success:enable

# Adesso (funziona su TUTTE le lingue):
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable
```

### Installazione

```powershell
# Download diretto
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cereZ23/sysmon/main/sysmon/deploy/windows-audit-policy.ps1" -OutFile "windows-audit-policy.ps1"

# Esegui (richiede Amministratore)
powershell.exe -ExecutionPolicy Bypass -File .\windows-audit-policy.ps1
```

### Parametri

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `-LogPath` | `C:\SecurityBaseline\Logs` | Percorso per backup e log |
| `-BackupExisting` | `$true` | Crea backup prima di applicare |
| `-RestoreDefaults` | `$false` | Ripristina policy di default |
| `-SysmonInstalled` | `$false` | Salta Process Creation/Termination (usa Sysmon) |

### Esempi

```powershell
# Configurazione standard
.\windows-audit-policy.ps1

# Con Sysmon installato (evita duplicati)
.\windows-audit-policy.ps1 -SysmonInstalled

# Ripristina default
.\windows-audit-policy.ps1 -RestoreDefaults

# Log path personalizzato
.\windows-audit-policy.ps1 -LogPath "D:\Logs\Audit"
```

### Eventi Abilitati

| Event ID | Descrizione | MITRE ATT&CK |
|----------|-------------|--------------|
| 4625 | Failed Logon | T1110 Brute Force |
| 4720 | User Account Created | T1136.001 Create Account |
| 4722 | User Account Enabled | T1098 Account Manipulation |
| 4724 | Password Reset | T1098 Account Manipulation |
| 4732 | Member Added to Group | T1098 Privilege Escalation |
| 4697 | Service Installed | T1543.003 Windows Service |
| 4698 | Scheduled Task Created | T1053.005 Scheduled Task |
| 4672 | Special Privileges | T1134 Token Manipulation |
| 4648 | Explicit Credentials | T1078 Valid Accounts |

### Output

```
[2025-12-29 15:59:40] [Info] Windows Audit Policy Configuration Script
[2025-12-29 15:59:40] [Info] Version 2.1.0 (Multi-Language Support)
[2025-12-29 15:59:40] [Success] Backup created successfully
[2025-12-29 15:59:41] [Info] Configuring: Logon (Success: True, Failure: True)
...
[2025-12-29 15:59:42] [Success] Configuration Complete
[2025-12-29 15:59:42] [Info] Policies configured successfully: 55
[2025-12-29 15:59:42] [Info] Policies failed: 0
```

---

## enable-powershell-logging.ps1

### Panoramica

Abilita il logging avanzato di PowerShell per la detection di attacchi.

### Eventi Abilitati

| Event ID | Log | Descrizione |
|----------|-----|-------------|
| 4103 | PowerShell/Operational | Module Logging |
| 4104 | PowerShell/Operational | Script Block Logging |

### Installazione

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\enable-powershell-logging.ps1
```

### Pattern di Attacco Rilevabili

| Pattern | Descrizione |
|---------|-------------|
| `-EncodedCommand` | Comando Base64 encoded |
| `Invoke-Expression` | Esecuzione dinamica |
| `DownloadString` | Download da Internet |
| `Invoke-Mimikatz` | Credential dumping |
| `FromBase64String` | Decodifica payload |

---

## CI/CD Testing

Entrambi gli script sono testati automaticamente in CI su:
- Windows Server 2025
- Locale Italiano (it-IT)
- Locale Tedesco (de-DE)
- Locale Francese (fr-FR)
- Locale Spagnolo (es-ES)

Vedi: [GitHub Actions Workflow](../../.github/workflows/sysmon-test.yml)

---

## Riferimenti

- [Microsoft Audit Policy Settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [PowerShell Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

**Versione:** 2.1.0
**Ultimo Aggiornamento:** Dicembre 2025
**Autore:** Security Engineering Team
