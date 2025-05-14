# DSViper - Antivirus Evasion Tool

DSViper is a tool designed for educational and ethical security testing purposes. It implements various antivirus evasion techniques to help security professionals understand and test defense mechanisms.

## Features

- Multiple encryption methods (XOR, AES)
- Various process injection techniques
- Process hollowing
- DLL side-loading
- Self-deleting malware simulation
- PowerShell execution
- AppLocker bypass techniques
- Indirect syscalls

## Implementations

This repository contains both Python and C++ implementations of the DSViper tool, providing the same functionality in both languages.

## Usage

**IMPORTANT**: This tool is intended for educational and ethical security testing purposes only. Use only in controlled lab environments with proper authorization.

### Python Version

```bash
python DSViper.py
```

### C++ Version

```bash
# Compile
g++ -o DSViper DSViper.cpp -lcrypto

# Run
./DSViper
```

## Disclaimer

This tool is provided for educational purposes only. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before using this tool in any environment.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
