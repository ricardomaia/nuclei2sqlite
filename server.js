const express = require('express');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('scan_history.db');

const PORT = 3000;

// Function to retrieve data from the database and execute the callback with the data
function getDataFromDatabase(sql, callback) {
    db.all(sql, (err, rows) => {
        if (err) {
            console.error('Error executing query:', err);
            callback(err, null);
        } else {
            callback(null, rows);
        }
    });
}

// Function to build the HTML table for a given report
function buildTable(header, data) {
    let tableHTML = `
    <h2>${header}</h2>
    <table class="table">
      <thead>
        <tr>
  `;

    const columns = Object.keys(data[0]);

    columns.forEach((column) => {
        tableHTML += `<th>${column}</th>`;
    });

    tableHTML += `
        </tr>
      </thead>
      <tbody>
  `;

    data.forEach((row) => {
        tableHTML += '<tr>';
        columns.forEach((column) => {
            tableHTML += `<td>${row[column]}</td>`;
        });
        tableHTML += '</tr>';
    });

    tableHTML += `
      </tbody>
    </table>
  `;

    return tableHTML;
}

// Middleware to set the layout for all routes
function setLayout(req, res, next) {
    res.sendLayout = (content) => {
        const html = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Scan History Reports</title>
            <link
              rel="stylesheet"
              href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css"
            />
          </head>
          <body>
            <div class="container">
              <h1>Scan History Reports</h1>
              ${content}
            </div>
          </body>
        </html>
      `;
        res.send(html);
    };
    next();
}

// Apply the layout middleware to all routes
app.use(setLayout);

// Route to display the navigation menu
app.get('/', (req, res) => {
    const content = `
    <ul class="list-group">
      <li class="list-group-item"><a href="/total-vulnerabilities">Total Vulnerabilities by Scan</a></li>
      <li class="list-group-item"><a href="/vulnerabilities-by-ip">Vulnerabilities by IP</a></li>
      <li class="list-group-item"><a href="/vulnerabilities-by-host">Vulnerabilities by Host</a></li>
      <li class="list-group-item"><a href="/vulnerabilities-by-severity">Vulnerabilities by Severity</a></li>
      <li class="list-group-item"><a href="/vulnerabilities-by-template">Vulnerabilities by Template ID</a></li>
      <li class="list-group-item"><a href="/all-vulnerabilities">All Vulnerabilities</a></li>
    </ul>
  `;

    res.sendLayout(content);
});

// Route to display the total vulnerabilities by scan date
app.get('/total-vulnerabilities', (req, res) => {
    const sql = `
    SELECT DATE(timestamp) as scan_date, COUNT(*) as total_vulnerabilities
    FROM scan_history
    GROUP BY DATE(timestamp)
    ORDER BY scan_date;
  `;

    getDataFromDatabase(sql, (err, data) => {
        if (err) {
            res.sendLayout('Error fetching data from the database.');
        } else {
            const tableHTML = buildTable('Total Vulnerabilities by Scan (grouped by date)', data);
            res.sendLayout(tableHTML);
        }
    });
});

// Route to display vulnerabilities by IP
app.get('/vulnerabilities-by-ip', (req, res) => {
    const sql = `
    SELECT ip, COUNT(*) as total_vulnerabilities
    FROM scan_history
    GROUP BY ip
    ORDER BY total_vulnerabilities DESC;
  `;

    getDataFromDatabase(sql, (err, data) => {
        if (err) {
            res.sendLayout('Error fetching data from the database.');
        } else {
            const tableHTML = buildTable('Vulnerabilities by IP', data);
            res.sendLayout(tableHTML);
        }
    });
});

// Route to display vulnerabilities by host
app.get('/vulnerabilities-by-host', (req, res) => {
    const sql = `
    SELECT host, COUNT(*) as total_vulnerabilities
    FROM scan_history
    GROUP BY host
    ORDER BY total_vulnerabilities DESC;
  `;

    getDataFromDatabase(sql, (err, data) => {
        if (err) {
            res.sendLayout('Error fetching data from the database.');
        } else {
            const tableHTML = buildTable('Vulnerabilities by Host', data);
            res.sendLayout(tableHTML);
        }
    });
});

// Route to display vulnerabilities by severity
app.get('/vulnerabilities-by-severity', (req, res) => {
    const sql = `
    SELECT severity, COUNT(*) as total_vulnerabilities
    FROM scan_history
    GROUP BY severity
    ORDER BY total_vulnerabilities DESC;
  `;

    getDataFromDatabase(sql, (err, data) => {
        if (err) {
            res.sendLayout('Error fetching data from the database.');
        } else {
            const tableHTML = buildTable('Vulnerabilities by Severity', data);
            res.sendLayout(tableHTML);
        }
    });
});

// Route to display vulnerabilities by template_id
app.get('/vulnerabilities-by-template', (req, res) => {
    const sql = `
    SELECT template, COUNT(*) as total_vulnerabilities
    FROM scan_history
    GROUP BY template
    ORDER BY total_vulnerabilities DESC;
  `;

    getDataFromDatabase(sql, (err, data) => {
        if (err) {
            res.sendLayout('Error fetching data from the database.');
        } else {
            const tableHTML = buildTable('Vulnerabilities by Template ID', data);
            res.sendLayout(tableHTML);
        }
    });
});

// Route to display all vulnerability details
app.get('/all-vulnerabilities', (req, res) => {
    const sql = `
    SELECT ip, host, DATE(timestamp) as scan_date, tags, extracted_results,
           cve_id, cwe_id, cvss_metrics, cvss_score, description, remediation,
           info_name, info_author, info_description, info_reference,
           info_severity, info_metadata_product, info_classification_cpe
    FROM scan_history;
  `;

    getDataFromDatabase(sql, (err, data) => {
        if (err) {
            res.sendLayout('Error fetching data from the database.');
        } else {
            // Convert info_reference string JSON into clickable links
            data.forEach((row) => {
                if (row.info_reference) {
                    try {
                        const references = JSON.parse(row.info_reference);
                        if (Array.isArray(references)) {
                            row.info_reference = references
                                .map((ref) => `<a href="${ref}" target="_blank">${ref}</a>`)
                                .join(', ');
                        }
                    } catch (error) {
                        console.error('Error parsing info_reference:', error);
                    }
                }
            });

            console.log(data);
            const tableHTML = buildTable('All Vulnerability Details', data);
            res.sendLayout(tableHTML);
        }
    });
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
