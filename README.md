# Nuclei2SQLite

Script to transform the JSON output of Nuclei to a SQLite database.

## Description

This is a Node.js project that allows you to do X, Y, and Z. It takes input from a JSON file and performs specific actions based on the data provided. The program can be used for tasks like A, B, and C, making it useful for developers working on certain projects.

## Usage

Create a Nuclei scan report in JSON format.

```console
nuclei -tags cve -l targets_file.txt -j -o scan-report.json
```

The first time, run the script with the `-c` option to create the database table.

```console
node nuclei2sqlite.js -c path/to/your/scan-report.json
```

Next time this will not be necessary.

```console
node nuclei2sqlite.js path/to/your/scan-report.json
```

Replace `scan-report.json` with the actual name of your JSON file.

### Other options

```console
Usage: nuclei2sqlite [options] <json_file_path>

Transform Nuclei JSON output to SQLite database

Options:
  -c, --create  Create the database
  -d, --delete  Delete existing records from the database
  -h, --help    display help for command
```

![image](https://github.com/ricardomaia/nuclei2sqlite/assets/1353811/8e9fa539-65c1-402b-a6bd-c1770e4979fa)

## Installation

- Make sure you have Node.js and npm installed on your system.
- Clone this repository to your local machine.
- Navigate to the project directory in the terminal or command prompt.
- Run the following command to install the dependencies:

```bash
npm install
```

## Examples of SQL queries

### Gereneral Report

```sql
SELECT ip, 
host, 
REPLACE(REPLACE(info_tags, '[', ''), ']', '') as tags, 
extracted_results,
cve_id, 
cwe_id, 
cvss_metrics, 
cvss_score, 
description, 
remediation,
info_name, 
info_description, 
REPLACE(REPLACE(info_reference, '[', ''), ']', '') as info_reference,
info_severity, 
info_metadata_product, 
info_classification_cpe
FROM scan_history
GROUP BY ip, host
ORDER BY
ip, host,
CASE info_severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
    ELSE 6
END;
```

![image](https://github.com/ricardomaia/nuclei2sqlite/assets/1353811/95b2abdb-b43a-4a71-92ad-47b0d1bbe6e7)


### WordPress outdated plugins

```sql

SELECT ip, 
host, 
extracted_results,
matcher_name,
meta,
info_name, 
REPLACE(REPLACE(info_tags, '[', ''), ']', '') as tags, 
REPLACE(REPLACE(info_reference, '[', ''), ']', '') as info_reference,
info_severity, 
info_metadata_product, 
info_classification_cpe
FROM scan_history
WHERE matcher_name = 'outdated_version'
GROUP BY ip, host
ORDER BY
ip, host
```

![image](https://github.com/ricardomaia/nuclei2sqlite/assets/1353811/dbe04239-76e7-4453-8283-0e7f3dfe4006)


### Outdated WordPress plugins (sorted by subdomain)

```sql
SELECT ip, 
host, 
extracted_results,
matcher_name,
meta,
info_name, 
REPLACE(REPLACE(info_tags, '[', ''), ']', '') as tags, 
REPLACE(REPLACE(info_reference, '[', ''), ']', '') as info_reference,
info_severity, 
info_metadata_product, 
info_classification_cpe
FROM scan_history
WHERE matcher_name = 'outdated_version'
ORDER BY SUBSTR(host, INSTR(host, '://') + 3, INSTR(host, '.subdomain.exemple.com') - (INSTR(host, '://') + 3));
```

### Total vulnerabilities per scan (grouped by date, ignoring hour and minute)

```sql
SELECT DATE(timestamp) as scan_date, COUNT(*) as total_vulnerabilities
FROM scan_history
GROUP BY DATE(timestamp)
ORDER BY scan_date;
```

### Vulnerabilities per IP

```sql
SELECT ip, COUNT(*) as total_vulnerabilities
FROM scan_history
GROUP BY ip
ORDER BY total_vulnerabilities DESC;
```

### Vulnerabilities per host

```sql
SELECT host, COUNT(*) as total_vulnerabilities
FROM scan_history
GROUP BY host
ORDER BY total_vulnerabilities DESC;
```

### Vulnerabilities per severity

```sql
SELECT severity, COUNT(*) as total_vulnerabilities
FROM scan_history
GROUP BY severity
ORDER BY total_vulnerabilities DESC;
```

### Vulnerabilities per template_id

```sql
SELECT template, COUNT(*) as total_vulnerabilities
FROM scan_history
GROUP BY template
ORDER BY total_vulnerabilities DESC;
```

## License

This project is licensed under the MIT License.
