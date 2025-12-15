# zscaler-settings
## check status
```powershell
Get-NetAdapterBinding -AllBindings -ComponentID ZS_ZAPPRD
```
## disable network adapter binding
```powershell
Get-NetAdapterBinding -AllBindings -ComponentID ZS_ZAPPRD | Disable-NetAdapterBinding
```
## enable network adapter binding
```powershell
Get-NetAdapterBinding -AllBindings -ComponentID ZS_ZAPPRD | Enable-NetAdapterBinding
```
