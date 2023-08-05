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
function buildTable(header, data, hide_columns = []) {
    let tableHTML = `
    <h2>${header}</h2>
    <table id="table"
    data-toggle="table"
    data-show-columns="true"
    data-search="true"
    data-show-toggle="true"
    data-pagination="true"
    data-resizable="true"
    data-page-size="10"
    data-virtual-scroll="true"
    data-search-highlight="true"
    data-detail-view="true"
    data-detail-formatter="detailFormatter"
    class="table table-striped table-hover table-bordered table-responsive-lg mw-100">
      <thead>
        <tr>
  `;

    const columns = Object.keys(data[0]);

    columns.forEach((column) => {
        tableHTML += `<th data-field="${column}"  data-sortable="true" data-search-highlight-formatter="customSearchFormatter">${column}</th>`;
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

    let hide_columns_script = '';
    if (hide_columns.length > 0) {
        hide_columns.map((column) => {
            hide_columns_script += `$table.bootstrapTable('hideColumn', '${column}');\n`;
        });
    }


    tableHTML += `
      </tbody>
    </table>
    <script>
        $(function() {
            $('#table').bootstrapTable()
        });

        window.customSearchFormatter = function(value, searchText) {
             return value.toString().replace(new RegExp('(' + searchText + ')', 'gim'), '<span style="background-color: pink;border: 1px solid red;border-radius:90px;padding:4px">$1</span>')
        }

        function detailFormatter(index, row) {
            var html = []
            $.each(row, function (key, value) {
            html.push('<p><b>' + key + ':</b> ' + value + '</p>')
        })
            return html.join('')
        }

        $(function() {
            var $table = $('#table');
            ${hide_columns_script}
        });
    </script>
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
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="description" content="">
            <meta name="author" content="Ricardo Maia">
            <title>Scan History Reports</title>

            <!-- jQuery -->
            <script src="https://code.jquery.com/jquery-3.7.0.min.js" integrity="sha256-2Pmvv0kuTBOenSvLm6bvfBSSHrUJ+3A7x6P5Ebd07/g=" crossorigin="anonymous">
            </script>

            <!-- Bootstrap -->
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css" />
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">

            <!-- Bootstrap Table -->
            <link rel="stylesheet" href="https://unpkg.com/bootstrap-table@1.22.1/dist/bootstrap-table.min.css">
            <script src="https://unpkg.com/bootstrap-table@1.22.1/dist/bootstrap-table.min.js"></script>


            <!-- Bootstrap Resizable Columns -->
            <link href="https://unpkg.com/jquery-resizable-columns@0.2.3/dist/jquery.resizableColumns.css" rel="stylesheet">
            <script src="https://unpkg.com/jquery-resizable-columns@0.2.3/dist/jquery.resizableColumns.min.js"></script>
            <script src="https://unpkg.com/bootstrap-table@1.22.1/dist/extensions/resizable/bootstrap-table-resizable.min.js"></script>



            <style>
                table {
                    table-layout: fixed;
                    word-wrap: break-word;
                    font-size: 0.8rem;
                }
            </style>
          </head>
          <body>
        <main class="container">
            <nav class="navbar navbar-expand-lg bg-body-tertiary">
            <div class="container-fluid">
                <a class="navbar-brand" href="/">Nuclei2SQLite</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavDropdown" aria-controls="navbarNavDropdown" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNavDropdown">
                <ul class="navbar-nav">
                    <li class="nav-item">
                    <a class="nav-link active" aria-current="page" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                    <a class="nav-link" href="/vulnerabilities-by-ip">by IP</a>
                    </li>
                    <li class="nav-item">
                    <a class="nav-link" href="/vulnerabilities-by-host">by Host</a>
                    </li>
                    <li class="nav-item">
                    <a class="nav-link" href="/vulnerabilities-by-severity">by Severity</a>
                    </li>
                    <li class="nav-item">
                    <a class="nav-link" href="/vulnerabilities-by-template">by Template ID</a>
                    </li>
                    <li class="nav-item">
                    <a class="nav-link" href="/all-vulnerabilities">All Vulnerabilities</a>
                    </li>

                </ul>
                </div>
            </div>
            </nav>


              ${content}
            </main>
          </body>
        </html>
      `;
        res.send(html);
    };
    next();
}

// Apply the layout middleware to all routes
app.use(setLayout);

// Route to display the total vulnerabilities by scan date
app.get('/', (req, res) => {
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
            const tableHTML = buildTable('Scan History', data);
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
    GROUP BY ip, host
    ORDER BY
    ip, host;
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
            const tableHTML = buildTable('All Vulnerability Details', data, hide_columns = ['extracted_results', 'info_reference', 'info_classification_cpe', 'info_metadata_product']);
            res.sendLayout(tableHTML);
        }
    });
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
