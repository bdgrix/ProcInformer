# Process Thread Monitor

A Windows tool that monitors and records thread creation across all running processes in real-time.

## Features

- Monitors all processes for new threads
- Records thread names, priorities, and CPU cycles
- Eliminates duplicate threads
- Creates beautiful formatted output
- Runs with high system privileges

## Requirements

- Windows 10 or 11
- .NET 8.0 Runtime
- Administrator privileges

## Installation

1. Download the latest release
2. Extract the files to any folder
3. Run `ProcInformer.exe` as Administrator

## Usage

1. Run the application as Administrator
2. Perform activities on your system
3. Return to the application
4. Press `Ctrl + C` to stop monitoring and save output

The application will create a file named `output-YYYY-MM-DD-HH-MM-SS.gtxt` with all thread information.

## Output

The tool generates clean, formatted tables showing:

- Thread ID and Name
- Base and Current Priority
- Priority Level
- Start Address
- CPU Cycle Data

## Building from Source

```bash
git clone https://github.com/bdgrix/ProcInformer
cd ProcInformer
dotnet build
