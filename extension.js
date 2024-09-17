const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const axios = require('axios');
const FormData = require('form-data');

let intruceptOutputChannel;

class IntruceptScansProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.data = ['Welcome to Intrucept Scans'];
    }

    getTreeItem(element) {
        return {
            label: element,
            collapsibleState: vscode.TreeItemCollapsibleState.None
        };
    }

    getChildren() {
        return this.data;
    }

    updateData(newData) {
        this.data = Array.isArray(newData) ? newData : [newData];
        this._onDidChangeTreeData.fire();
    }
}

function activate(context) {
    console.log('Intrucept AppSecOps extension is now active');

    const intruceptScansProvider = new IntruceptScansProvider();
    vscode.window.registerTreeDataProvider('intruceptScans', intruceptScansProvider);
    vscode.commands.registerCommand('intruceptScans.refreshEntry', () => intruceptScansProvider.updateData(['Refreshed']));

    intruceptOutputChannel = vscode.window.createOutputChannel("Intrucept Scans");

    let sastDisposable = vscode.commands.registerCommand('sast-scan.performScan', () => performScan('SAST', intruceptScansProvider));
    let scaDisposable = vscode.commands.registerCommand('sca-scan.performScan', () => performScan('SCA', intruceptScansProvider));

    context.subscriptions.push(sastDisposable, scaDisposable, intruceptOutputChannel);
}

async function performScan(scanType, provider) {
    const workspaceFolder = vscode.workspace.workspaceFolders[0];
    const projectName = workspaceFolder.name;
    const projectPath = workspaceFolder.uri.fsPath;
    const zipPath = path.join(projectPath, 'project.zip');

    // Update the view with the scan initiation message
    provider.updateData([`${scanType} Scan initiated on ${projectName}`, new Date().toLocaleString()]);

    try {
        updateOutput(`Initiating ${scanType} scan on ${projectName}...`, provider);

        const config = await readConfig(projectPath);
        if (!config) {
            updateOutput('Failed to read intrucept-config.txt. Please ensure it exists in the project root.', provider);
            return;
        }

        await createZip(projectPath, zipPath);

        updateOutput(`Sending ${scanType} scan request...`, provider);
        const response = await sendScanRequest(zipPath, scanType, config);

        console.log(response)
        
        vscode.window.showInformationMessage(`${scanType} scan completed successfully.`);
        
        if (response.data) {
            if (response.data.vulnsTable.trim() === '') {
                updateOutput("No vulnerabilities were found.", provider);
            } else {
                updateOutput(response.data.vulnsTable, provider);
            }
        } else {
            updateOutput(`${scanType} scan completed, but no vulnerability data was returned.`, provider);
        }
        

    } catch (error) {
        vscode.window.showErrorMessage(`Error during ${scanType} scan: ${error.message}`);
        updateOutput(`Error during ${scanType} scan: ${error.message}`, provider);
    } finally {
        // Clean up the zip file
        if (fs.existsSync(zipPath)) {
            fs.unlinkSync(zipPath);
        }
    }
}

function updateOutput(content, provider) {
    if (typeof content === 'object') {
        content = JSON.stringify(content, null, 2);
    }
    intruceptOutputChannel.appendLine(content);
    intruceptOutputChannel.show(true);
    if (provider && typeof provider.updateData === 'function') {
        provider.updateData([content, 'See Output for details']);
    }
}
function readConfig(workspaceFolder) {
    return new Promise((resolve) => {
        const configPath = path.join(workspaceFolder, 'intrucept-config.txt');
        fs.readFile(configPath, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading config file:', err);
                resolve(null);
                return;
            }

            const config = {};
            data.split('\n').forEach(line => {
                const [key, value] = line.split('=').map(part => part.trim());
                if (key && value) {
                    config[key] = value;
                }
            });

            resolve(config);
        });
    });
}

function createZip(sourceDir, outputPath) {
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(outputPath);
        const archive = archiver('zip', { zlib: { level: 9 } });

        output.on('close', resolve);
        archive.on('error', reject);

        archive.pipe(output);

        const tempDir = path.join(sourceDir, 'temp_project_folder');
        fs.mkdirSync(tempDir, { recursive: true });

        // Copy project files to temp directory
        fs.readdirSync(sourceDir).forEach(item => {
            const itemPath = path.join(sourceDir, item);
            if (item !== 'node_modules' && item !== '.git' && item !== 'intrucept-config.txt' && item !== 'temp_project_folder') {
                if (fs.lstatSync(itemPath).isDirectory()) {
                    fs.cpSync(itemPath, path.join(tempDir, item), { recursive: true });
                } else {
                    fs.copyFileSync(itemPath, path.join(tempDir, item));
                }
            }
        });

        // Add temp directory to the archive
        archive.directory(tempDir, 'project');

        archive.finalize();

        // Clean up temp directory after zipping
        output.on('close', () => {
            fs.rmSync(tempDir, { recursive: true, force: true });
            resolve();
        });
    });
}

async function sendScanRequest(zipPath, scanType, config) {
    const formData = new FormData();
    formData.append('projectZipFile', fs.createReadStream(zipPath));
    formData.append('applicationId', config.APPLICATION_ID);
    formData.append('scanName', `New ${scanType} Scan from VS Code Extension`);
    formData.append('language', 'python'); // You might want to detect this dynamically

    const apiUrl = scanType === 'SAST' 
        ? 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/performSASTScan'
        : 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/performSCAScan';

    return axios.post(apiUrl, formData, {
        headers: {
            ...formData.getHeaders(),
            'Client-ID': config.CLIENT_ID,
            'Client-Secret': config.CLIENT_SECRET
        }
    });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
}