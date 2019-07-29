## libnss-llmnr-wsl
An NSS module providing LLMNR lookup for WSL.

## How it works
This package simply calls `powershell.exe` to perform the LLMNR lookup with the following command:
```powershell
try {
    (Resolve-DnsName -Name {0} -Type {1} -LlmnrOnly -ErrorAction Stop).IPAddress;
} catch {
    exit 1;
}
```

## Installation
See release page.

Since launching PowerShell is slow, please place `llmnr_wsl` to the very last in the `hosts` list in `/etc/nsswitch.conf`. Example:
```
hosts: files dns llmnr_wsl
```
