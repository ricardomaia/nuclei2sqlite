/**
 * Nuclei to SQLite
 *
 * This script will transform the JSON output of Nuclei to a SQLite database.
 *
 * @version 0.1.0
 * @author Ricardo Maia
 * @license MIT
 * @link https://github.com/ricardomaia/nuclei2sqlite
 *
 * @created 2023-08-03
 * @updated 2023-08-03
 * @usage node nuclei2sqlite.js -c -d nuclei_output.json
 */

const fs = require("fs");
const readline = require('readline');
const { v4: uuidv4 } = require("uuid");
const sqlite3 = require("sqlite3").verbose();
const { program } = require('commander');
const path = require('path');


function parseField(field) {
    if (Array.isArray(field)) {
        return JSON.stringify(field);
    } else if (typeof field === 'object' && field !== null) {
        return JSON.stringify(field);
    }
    return field;
}


const db = new sqlite3.Database("scan_history.db");


program
    .name('nuclei2sqlite')
    .description('Transform Nuclei JSON output to SQLite database')
    .option('-c, --create', 'Create the database')
    .option('-d, --delete', 'Delete existing records from the database')
    .arguments('<json_file_path>')
    .action((jsonFilePath) => {

        const filteredFileName = path.basename(jsonFilePath);

        // Check if the file exists before accepting
        if (!fs.existsSync(filteredFileName)) {
            console.error(`The specified file '${filteredFileName}' does not exist.`);
            process.exit(1);
        }

        const readStream = fs.createReadStream(jsonFilePath, {
            encoding: 'utf-8',
        });

        const rl = readline.createInterface({
            input: readStream,
            crlfDelay: Infinity,
        });

        let jsonLine = '';
        let lineNumber = 0; // Counter for line number

        db.serialize(() => {

            if (program.getOptionValue('create')) {

                db.run(`
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id TEXT PRIMARY KEY,
                        template TEXT,
                        host TEXT,
                        ip TEXT,
                        timestamp TEXT,
                        severity TEXT,
                        curl_command TEXT,
                        extractor_name TEXT,
                        extracted_results TEXT,
                        cve_id TEXT,
                        cwe_id TEXT,
                        cvss_metrics TEXT,
                        cvss_score TEXT,
                        description TEXT,
                        remediation TEXT,
                        info_name TEXT,
                        info_author TEXT,
                        info_tags TEXT,
                        info_description TEXT,
                        info_reference TEXT,
                        info_severity TEXT,
                        info_metadata_vendor TEXT,
                        info_metadata_product TEXT,
                        info_metadata_max_request TEXT,
                        info_metadata_epss_score TEXT,
                        info_classification_cve_id TEXT,
                        info_classification_cwe_id TEXT,
                        info_classification_cvss_metrics TEXT,
                        info_classification_cvss_score TEXT,
                        info_classification_epss_score TEXT,
                        info_classification_cpe TEXT,
                        type TEXT,
                        matched_at TEXT,
                        request TEXT,
                        response TEXT,
                        matcher_status TEXT,
                        matcher_name TEXT,
                        meta TEXT
                    )
                `);
            }

            if (program.getOptionValue('delete')) {
                db.run(`DELETE FROM scan_history`, (error) => {
                    if (error) {
                        console.error('Error deleting records:', error);
                        process.exit(1);
                    } else {
                        console.log('Records deleted.');
                    }
                });
            }

            const stmt = db.prepare(`
                INSERT INTO scan_history (
                    id, template, host, ip, timestamp, severity, curl_command,
                    extractor_name, extracted_results, cve_id, cwe_id, cvss_metrics,
                    cvss_score, description, remediation,
                    info_name, info_author, info_tags, info_description, info_reference,
                    info_severity, info_metadata_vendor, info_metadata_product, info_metadata_max_request,
                    info_metadata_epss_score, info_classification_cve_id, info_classification_cwe_id,
                    info_classification_cvss_metrics, info_classification_cvss_score,
                    info_classification_epss_score, info_classification_cpe,
                    type, matched_at, request, response, matcher_status, matcher_name, meta
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            rl.on('line', (line) => {
                jsonLine += line;
                lineNumber++;
                console.log(`Processing line ${lineNumber} of the file...`);
                try {
                    const jsonObject = JSON.parse(jsonLine);
                    //console.log(jsonObject);
                    const UUID = uuidv4();
                    const extracted_results = parseField(jsonObject["extracted-results"]);
                    const cve_id = parseField(jsonObject["info"]["classification"]?.["cve-id"]?.[0]);
                    const cwe_id = parseField(jsonObject["info"]["classification"]?.["cwe-id"]?.[0]);
                    const info_author = parseField(jsonObject["info"]["author"]);
                    const template = jsonObject["template-id"] ?? null;
                    const host = jsonObject["host"] ?? null;
                    const ip = jsonObject["ip"] ?? "0.0.0.0";
                    const severity = jsonObject["info"]["severity"] ?? null;
                    const timestamp = jsonObject["timestamp"];
                    const curl_command = jsonObject["curl-command"] ?? "";
                    const regex = /'/gm;
                    const subst = `''`;
                    const curl_command_escaped = curl_command.replace(regex, subst);
                    const extractor_name = jsonObject["extractor-name"] ?? null;
                    const cvss_metrics = jsonObject["info"]["classification"]?.["cvss-metrics"] ?? null;
                    const cvss_score = jsonObject["info"]["classification"]?.["cvss-score"] ?? null;
                    const description = jsonObject["info"]["classification"]?.["description"] ?? null;
                    const remediation = jsonObject["info"]["classification"]?.["remediation"] ?? null;
                    const info_name = jsonObject["info"]["name"] ?? null;
                    const info_tags = parseField(jsonObject["info"]["tags"]) ?? null;
                    const info_description = jsonObject["info"]["description"] ?? null;
                    const info_reference = parseField(jsonObject["info"]["reference"]) ?? null;
                    const info_severity = jsonObject["info"]["severity"] ?? null;
                    const info_metadata_vendor = jsonObject["info"]["metadata"]?.["vendor"] ?? null;
                    const info_metadata_product = jsonObject["info"]["metadata"]?.["product"] ?? null;
                    const info_metadata_max_request = jsonObject["info"]["metadata"]?.["max-request"] ?? null;
                    const info_metadata_epss_score = jsonObject["info"]["metadata"]?.["epss-score"] ?? null;
                    const info_classification_cve_id = jsonObject["info"]["classification"]?.["cve-id"]?.[0] ?? null;
                    const info_classification_cwe_id = jsonObject["info"]["classification"]?.["cwe-id"]?.[0] ?? null;
                    const info_classification_cvss_metrics = jsonObject["info"]["classification"]?.["cvss-metrics"] ?? null;
                    const info_classification_cvss_score = jsonObject["info"]["classification"]?.["cvss-score"] ?? null;
                    const info_classification_epss_score = jsonObject["info"]["classification"]?.["epss-score"] ?? null;
                    const info_classification_cpe = jsonObject["info"]["classification"]?.["cpe"] ?? null;
                    const matcher_name = jsonObject["matcher-name"] ?? null;
                    const meta = parseField(jsonObject["meta"]) ?? null;

                    stmt.run(
                        UUID,
                        template,
                        host,
                        ip,
                        timestamp,
                        severity,
                        curl_command_escaped,
                        extractor_name,
                        extracted_results,
                        cve_id,
                        cwe_id,
                        cvss_metrics,
                        cvss_score,
                        description,
                        remediation,
                        info_name,
                        info_author,
                        info_tags,
                        info_description,
                        info_reference,
                        info_severity,
                        info_metadata_vendor,
                        info_metadata_product,
                        info_metadata_max_request,
                        info_metadata_epss_score,
                        info_classification_cve_id,
                        info_classification_cwe_id,
                        info_classification_cvss_metrics,
                        info_classification_cvss_score,
                        info_classification_epss_score,
                        info_classification_cpe,
                        jsonObject["type"],
                        jsonObject["matched-at"],
                        jsonObject["request"],
                        jsonObject["response"],
                        jsonObject["matcher-status"],
                        matcher_name,
                        meta
                    );

                    jsonLine = '';
                } catch (error) {
                    console.log(error);
                }
            });

            rl.on('close', () => {
                console.log('Done.');
                stmt.finalize(() => {
                    db.close();
                });
            });
        });
    });

program.parse(process.argv);
