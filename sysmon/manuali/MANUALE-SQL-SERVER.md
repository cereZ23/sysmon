# Manuale Configurazione Sicurezza - SQL Server (SQL)

**Versione:** 1.0
**Data:** 23 Dicembre 2025
**Target:** Microsoft SQL Server 2016/2019/2022

---

## 1. Panoramica

SQL Server richiede una configurazione specifica per bilanciare sicurezza e performance. Il focus è sul rilevamento di SQL injection, xp_cmdshell abuse e credential theft.

### Profilo di Rischio SQL Server

| Caratteristica | Valore |
|----------------|--------|
| Esposizione | ALTA (contiene dati business critici) |
| Attacchi comuni | SQL injection, xp_cmdshell, data exfiltration |
| Volume eventi | ALTO (query engine molto attivo) |
| Priorità | Protezione dati, rilevamento command execution |

### Minacce Specifiche SQL Server

| Minaccia | Tecnica | Rilevamento |
|----------|---------|-------------|
| xp_cmdshell Abuse | T1059.001 | Sysmon (sqlservr.exe → cmd/ps) |
| SQL Agent Job Abuse | T1053 | Sysmon (SQLAGENT → cmd/ps) |
| Linked Server Abuse | T1021 | SQL Audit + Sysmon |
| Data Exfiltration | T1048 | Network monitoring |
| Credential Access | T1552 | Sysmon (registry access) |

---

## 2. Installazione Sysmon

### 2.1 Pre-Requisiti

```powershell
# Verificare che SQL Server sia in manutenzione o basso carico
# Sysmon può causare piccolo overhead

# Verificare servizi SQL attivi
Get-Service | Where-Object {$_.DisplayName -like "*SQL*"}
```

### 2.2 Installazione

```powershell
# 1. Copiare i file
Copy-Item "Sysmon64.exe" -Destination "C:\Tools\"
Copy-Item "sysmon-sql.xml" -Destination "C:\Tools\"

# 2. Installare
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-sql.xml

# 3. Verificare
Get-Service Sysmon64
```

### 2.3 Caratteristiche Configurazione SQL

La configurazione `sysmon-sql.xml` include:
- Esclusioni per processi SQL normali (riduce noise)
- Regole AND per sqlservr.exe → shell (CRITICO)
- Monitoraggio xp_cmdshell patterns
- Esclusione backup operations

---

## 3. Eventi Sysmon per SQL Server

### 3.1 Regole Critiche (AND Rules)

```xml
<!-- CRITICO: SQL Server che spawna shell = xp_cmdshell abuse -->
<Rule groupRelation="and">
  <ParentImage condition="end with">\sqlservr.exe</ParentImage>
  <Image condition="image">cmd.exe</Image>
</Rule>
<Rule groupRelation="and">
  <ParentImage condition="end with">\sqlservr.exe</ParentImage>
  <Image condition="image">powershell.exe</Image>
</Rule>

<!-- SQL Agent che spawna shell = Job abuse -->
<Rule groupRelation="and">
  <ParentImage condition="end with">\SQLAGENT.EXE</ParentImage>
  <Image condition="image">cmd.exe</Image>
</Rule>
```

### 3.2 CommandLine Patterns

```xml
<!-- SQL-specific attack indicators -->
<CommandLine condition="contains">xp_cmdshell</CommandLine>
<CommandLine condition="contains">sp_configure</CommandLine>
<CommandLine condition="contains">OPENROWSET</CommandLine>
<CommandLine condition="contains">OPENDATASOURCE</CommandLine>
<CommandLine condition="contains">xp_regread</CommandLine>
<CommandLine condition="contains">xp_regwrite</CommandLine>
<CommandLine condition="contains">xp_dirtree</CommandLine>
```

---

## 4. Windows Security Events

### 4.1 Eseguire Audit Policy

```powershell
.\deploy\windows-audit-policy.ps1 -SysmonInstalled
```

### 4.2 Eventi Critici per SQL Server

| Event ID | Descrizione | Importanza |
|----------|-------------|------------|
| 4624 | Logon (Type 3 = Network) | MEDIO |
| 4625 | Logon Failed (brute force) | ALTO |
| 4648 | Explicit Credentials | ALTO |
| 4697 | Service Installed | CRITICO |
| 4688 | Process Creation* | ALTO |

*Solo se Sysmon non installato

---

## 5. SQL Server Audit (Complementare)

### 5.1 Abilitare SQL Server Audit

```sql
-- Creare Server Audit
CREATE SERVER AUDIT SQLSecurityAudit
TO FILE (FILEPATH = 'C:\SQLAudit\', MAXSIZE = 1 GB)
WITH (ON_FAILURE = CONTINUE);
GO

ALTER SERVER AUDIT SQLSecurityAudit WITH (STATE = ON);
GO

-- Creare Server Audit Specification
CREATE SERVER AUDIT SPECIFICATION ServerAuditSpec
FOR SERVER AUDIT SQLSecurityAudit
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
ADD (BACKUP_RESTORE_GROUP),
ADD (DBCC_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (DATABASE_PERMISSION_CHANGE_GROUP)
WITH (STATE = ON);
GO
```

### 5.2 Audit xp_cmdshell Usage

```sql
-- Creare audit per xp_cmdshell
CREATE DATABASE AUDIT SPECIFICATION XpCmdShellAudit
FOR SERVER AUDIT SQLSecurityAudit
ADD (EXECUTE ON OBJECT::[sys].[xp_cmdshell] BY [public])
WITH (STATE = ON);
GO
```

---

## 6. Regole di Rilevamento

### 6.1 xp_cmdshell Abuse (CRITICO)

**Sysmon Detection:**
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)sqlservr\.exe$")
| where match(Image, "(?i)(cmd|powershell|pwsh)\.exe$")
| table _time, ComputerName, User, Image, CommandLine, ParentCommandLine
```

**Priorità:** P1 - Escalation immediata

### 6.2 SQL Agent Job Abuse

```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)SQLAGENT\.EXE$")
| where match(Image, "(?i)(cmd|powershell)\.exe$")
| where NOT match(CommandLine, "(?i)(backup|maintenance|index)")
| table _time, ComputerName, User, Image, CommandLine
```

### 6.3 OPENROWSET/OPENDATASOURCE Abuse

```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)(OPENROWSET|OPENDATASOURCE)")
| table _time, ComputerName, User, CommandLine
```

### 6.4 Failed SQL Logins

```spl
index=sqlerror source="ERRORLOG*"
| where match(_raw, "Login failed")
| stats count by src_ip, user
| where count > 10
```

---

## 7. Checklist Deployment

### Pre-Deployment

- [ ] Pianificare manutenzione SQL
- [ ] Backup database critici
- [ ] Verificare workload SQL attuale
- [ ] Notificare team DBA

### Deployment

- [ ] Installare Sysmon con `sysmon-sql.xml`
- [ ] Eseguire `windows-audit-policy.ps1 -SysmonInstalled`
- [ ] Configurare SQL Server Audit
- [ ] Eseguire `enable-powershell-logging.ps1`

### Post-Deployment

- [ ] Monitorare performance SQL per 24h
- [ ] Verificare query response time
- [ ] Controllare eventi Sysmon generati
- [ ] Configurare forwarding SIEM

---

## 8. Configurazione Event Log

```powershell
# SQL Server genera molti eventi
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824  # 1GB
wevtutil sl "Security" /ms:2147483648  # 2GB
wevtutil sl "Application" /ms:536870912  # 512MB (SQL errors)
```

---

## 9. Hardening SQL Server

### 9.1 Disabilitare xp_cmdshell (se non necessario)

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

### 9.2 Rimuovere BUILTIN\Administrators

```sql
-- Verificare membri sysadmin
SELECT name FROM sys.server_principals
WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;

-- Rimuovere se presente
DROP LOGIN [BUILTIN\Administrators];
```

### 9.3 Abilitare Transparent Data Encryption

```sql
-- Proteggere dati at rest
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'ComplexPassword123!';
CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate';
-- ... (continua configurazione TDE)
```

---

## 10. Alert da Configurare

| Alert | Priorità | Trigger |
|-------|----------|---------|
| xp_cmdshell Executed | P1 | sqlservr.exe → cmd/ps |
| SQL Brute Force | P2 | >10 failed logins/5min |
| SA Login Used | P2 | Login with 'sa' account |
| New SQL Login Created | P3 | Server role change |
| Database Backup to Network | P3 | Backup to UNC path |

---

## Appendice A: Processi SQL Normali (Esclusioni)

| Processo | Descrizione | Escludere |
|----------|-------------|-----------|
| sqlservr.exe | SQL Engine | Solo per eventi normali |
| SQLAGENT.EXE | SQL Agent | Solo per job normali |
| sqlwriter.exe | VSS Writer | Sì |
| fdhost.exe | Full-text search | Sì |
| sqlceip.exe | Telemetry | Sì |

## Appendice B: MITRE ATT&CK Coverage

| Tecnica | ID | Coverage |
|---------|-----|----------|
| xp_cmdshell | T1059.001 | Sysmon AND rules |
| SQL Stored Procedures | T1059.001 | SQL Audit |
| OS Credential Dumping | T1003 | Sysmon 10 |
| Data from Database | T1213 | SQL Audit |
| Scheduled Task via Agent | T1053 | Sysmon |

---

**Documento Version:** 1.0
**Autore:** Security Engineering Team
**Prossima Revisione:** Marzo 2026
