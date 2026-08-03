# zscaler-settings
## install 
```sh
curl -fsSL https://raw.githubusercontent.com/chubbyhippo/zscaler-settings/refs/heads/main/setup.sh | sh
```
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
