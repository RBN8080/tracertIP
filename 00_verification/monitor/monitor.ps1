<#
tracertIP - F0 - abre las vistas de monitoreo del nodo, cada una en su propia
ventana de Windows Terminal, por SSH. Antes despliega monitor.sh en el nodo
(~/tracertip-monitor.sh) si la copia no coincide por SHA-256 (P1: nada se
edita a mano en el nodo).

  .\00_verification\monitor\monitor.ps1 -Nodo <alias ssh>                 # vistas por omision
  .\00_verification\monitor\monitor.ps1 -Nodo <alias> -Vistas diario,red  # solo esas
  .\00_verification\monitor\monitor.ps1 -Nodo <alias> -WhatIf             # muestra, no abre

El alias sale de -Nodo o de la variable de entorno TRACERTIP_NODO (P4).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Nodo = $env:TRACERTIP_NODO,
    [ValidateSet('proceso', 'tablero', 'trafico', 'centinela', 'sockets', 'alertas', 'diario', 'red')]
    [string[]]$Vistas = @('proceso', 'tablero', 'trafico', 'centinela', 'sockets', 'alertas')
)
$ErrorActionPreference = 'Stop'
if (-not $Nodo) { throw 'Falta el nodo: -Nodo <alias ssh> o TRACERTIP_NODO.' }

$local = Join-Path $PSScriptRoot 'monitor.sh'
$remoto = 'tracertip-monitor.sh'   # en el home del usuario del nodo
$hash = (Get-FileHash -Algorithm SHA256 $local).Hash.ToLower()
$enNodo = (ssh -o ConnectTimeout=8 $Nodo "sha256sum $remoto 2>/dev/null | cut -d' ' -f1")
if ($LASTEXITCODE -ne 0) { throw "Sin SSH al nodo '$Nodo'." }
if ($enNodo -ne $hash -and $PSCmdlet.ShouldProcess("${Nodo}:$remoto", 'desplegar monitor.sh')) {
    scp -q $local "${Nodo}:$remoto"
    $enNodo = (ssh $Nodo "sha256sum $remoto | cut -d' ' -f1")
    if ($enNodo -ne $hash) { throw "La copia en el nodo no coincide (SHA-256 $enNodo)." }
    Write-Host "Desplegado ${Nodo}:$remoto ($hash)"
}

foreach ($v in $Vistas) {
    if ($PSCmdlet.ShouldProcess($v, 'abrir ventana')) {
        # Sin espacios en ningun argumento: Start-Process no los entrecomilla.
        # La tilde llega literal a ssh y la expande el shell del nodo.
        Start-Process wt.exe -ArgumentList @('-w', 'new', '--title', "tracertIP-$v",
            'ssh', '-t', $Nodo, 'sh', "~/$remoto", $v)
    }
}
