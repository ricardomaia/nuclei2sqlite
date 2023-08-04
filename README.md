# Nuclei2SQLite

Script to transform the JSON output of Nuclei to a SQLite database.

## Description
This is a Node.js project that allows you to do X, Y, and Z. It takes input from a JSON file and performs specific actions based on the data provided. The program can be used for tasks like A, B, and C, making it useful for developers working on certain projects.

## Usage

First you need to create a Nuclei scan report in JSON format.

```console
nuclei -tags cve -l targets_file.txt -j -o scan-report.json
```
So execute the nuclei2sqlite.js script.

```console
node nuclei2sqlite.js path/to/your/scan-report.json
```

Replace `scan-report.json` with the actual name of your JSON file.

## Installation
- Make sure you have Node.js and npm installed on your system.
- Clone this repository to your local machine.
- Navigate to the project directory in the terminal or command prompt.
- Run the following command to install the dependencies:
  
```bash
npm install
```

## License
This project is licensed under the MIT License.
