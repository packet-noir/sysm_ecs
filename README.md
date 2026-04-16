# sysmon-ecs

Ingests Sysmon Event ID 1 XML and normalizes process creation fields to Elastic Common Schema (ECS).

## Dependencies

Python 3.x

## Usage

```
python sysmon_ecs.py absolute/path/to/eventid1.xml
```

## Sample Output

```
{'process.command_line': '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
 'process.executable': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
 'process.name': 'powershell.exe',
 'process.parent.executable': 'C:\\Windows\\explorer.exe',
 'user.name': 'windows-vmware\\sukuna'}
```