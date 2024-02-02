# Liberated, Light-weight, Leak-proof Logs (llllogs)

Parses a set of log files and saves them to a structured database.

User identifiable information is hashed and saved to sub-tables that can be
`DROP`ped to pseudonomise the data. The hashed columns in the main table could be
`UPDATE`d to an auto-incrementing index to anonymise the data, or erased completely
to remove all user behaviour from the data.

## For users

### Install the required packages

```sh
python -m venv .venv --prompt llllogs
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the script against the demo log file

```sh
source .venv/bin/activate
./llllogs.py demo.log
```

## For developers

### Install the required packages

```sh
python -m venv .venv --prompt llllogs
source .venv/bin/activate
pip install -r dev-requirements.txt
git config core.hooksPath .githooks
```

### Debug with Visual Studio Code

Install Microsoft's
[Python extension](https://marketplace.visualstudio.com/items?itemName=ms-python.python),
if you haven't already. Then launch vscode from within the project's activated
virtualenv.

```sh
$ source .venv/bin/activate
$ code .
```

Add the following `.vscode/launch.json` snippet.

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug llllogs",
            "type": "python",
            "request": "launch",
            "program": "llllogs.py",
            "args": [
                "demo.log"
            ],
            "console": "integratedTerminal",
            "justMyCode": true,
            "preLaunchTask": "rm-db"
        }
    ]
}
```

Add the following `.vscode/tasks.json` snippet.

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "rm-db",
            "type": "shell",
            "command": "rm logs.db || true",
        }
    ]
}
```

### Linting the project

Linting is automatically run by the pre-commit git hook, but to manually lint the
project run the `.githooks/pre-commit` script.
