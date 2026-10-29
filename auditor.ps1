#Requires -RunAsAdministrator

<#.SYNOPSIS
    Auditor de Seguranca Windows (baseline inspirada no CIS Benchmark).
.DESCRIPTION
    Verifica configuracoes de seguranca do Windows e gera relatorio em HTML e JSON.
    Autora: Clara Araujo (github.com/claraaraujodv)
#>

# ============================================================
# 1. ESTRUTURA: lista onde guardamos o resultado de cada checagem
# ============================================================
$Resultados = @()

function Add-Resultado {
    param(
        [string]$Id,
        [string]$Checagem,
        [string]$Esperado,
        [string]$Encontrado,
        [string]$Status,        # APROVADO, REPROVADO ou ERRO
        [string]$Recomendacao
    )
    $script:Resultados += [PSCustomObject]@{
        ID           = $Id
        Checagem     = $Checagem
        Esperado     = $Esperado
        Encontrado   = $Encontrado
        Status       = $Status
        Recomendacao = if ($Status -eq 'APROVADO') { '-' } else { $Recomendacao }
    }
}

function Get-Status([bool]$ok) { if ($ok) { 'APROVADO' } else { 'REPROVADO' } }

# ============================================================
# 2. LER A POLITICA DE SEGURANCA LOCAL (senha, bloqueio de conta)
#    secedit exporta a politica para um arquivo de texto
# ============================================================
$cfg = Join-Path $env:TEMP 'secpol.cfg'
secedit /export /cfg $cfg /areas SECURITYPOLICY | Out-Null
$Politica = Get-Content $cfg

function Get-Politica([string]$Nome) {
    $linha = $Politica | Where-Object { $_ -match "^$Nome\s*=" }
    if ($linha) { return [int](($linha -split '=')[1].Trim()) }
    return $null
}

# ============================================================
# 3. CHECAGENS
#    Padrao de cada uma: ler o valor -> comparar -> Add-Resultado
# ============================================================

# --- CHECAGEM 1: Firewall ativo em todos os perfis ---
try {
    foreach ($perfil in Get-NetFirewallProfile) {
        $ativo = "$($perfil.Enabled)" -eq 'True'
        Add-Resultado -Id "FW-$($perfil.Name)" `
            -Checagem "Firewall ativo (perfil $($perfil.Name))" `
            -Esperado 'True' -Encontrado "$($perfil.Enabled)" `
            -Status (Get-Status $ativo) `
            -Recomendacao "Set-NetFirewallProfile -Profile $($perfil.Name) -Enabled True"
    }
} catch {
    Add-Resultado -Id 'FW' -Checagem 'Firewall' -Esperado 'True' `
        -Encontrado "Erro: $($_.Exception.Message)" -Status 'ERRO' -Recomendacao 'Verificar manualmente'
}

# --- CHECAGEM 2: Protecao em tempo real do Defender ---
try {
    $defender = (Get-MpComputerStatus).RealTimeProtectionEnabled
    Add-Resultado -Id 'AV-01' -Checagem 'Defender: protecao em tempo real' `
        -Esperado 'True' -Encontrado "$defender" -Status (Get-Status $defender) `
        -Recomendacao 'Set-MpPreference -DisableRealtimeMonitoring $false'
} catch {
    Add-Resultado -Id 'AV-01' -Checagem 'Defender: protecao em tempo real' -Esperado 'True' `
        -Encontrado 'Defender indisponivel (outro antivirus?)' -Status 'ERRO' -Recomendacao 'Verificar o antivirus instalado'
}

# --- CHECAGEM 3: SMBv1 desativado (protocolo antigo, explorado pelo WannaCry) ---
try {
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    Add-Resultado -Id 'NET-01' -Checagem 'SMBv1 desativado' `
        -Esperado 'False' -Encontrado "$smb1" -Status (Get-Status (-not $smb1)) `
        -Recomendacao 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'
} catch {
    Add-Resultado -Id 'NET-01' -Checagem 'SMBv1 desativado' -Esperado 'False' `
        -Encontrado "Erro: $($_.Exception.Message)" -Status 'ERRO' -Recomendacao 'Verificar manualmente'
}

# --- CHECAGEM 4: UAC ativo (lido do registro) ---
try {
    $uac = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    Add-Resultado -Id 'SYS-01' -Checagem 'UAC ativo' `
        -Esperado '1' -Encontrado "$uac" -Status (Get-Status ($uac -eq 1)) `
        -Recomendacao 'Ativar o UAC (EnableLUA = 1) e reiniciar'
} catch {
    Add-Resultado -Id 'SYS-01' -Checagem 'UAC ativo' -Esperado '1' `
        -Encontrado 'Chave nao encontrada' -Status 'ERRO' -Recomendacao 'Verificar manualmente'
}

# --- CHECAGEM 5: Conta Convidado desativada ---
# Usamos o SID terminado em -501 porque o nome muda conforme o idioma (Guest/Convidado)
try {
    $convidado = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
    $desativada = -not $convidado.Enabled
    Add-Resultado -Id 'ACC-01' -Checagem 'Conta Convidado desativada' `
        -Esperado 'Desativada' -Encontrado $(if ($desativada) { 'Desativada' } else { 'Ativa' }) `
        -Status (Get-Status $desativada) `
        -Recomendacao "Disable-LocalUser -Name '$($convidado.Name)'"
} catch {
    Add-Resultado -Id 'ACC-01' -Checagem 'Conta Convidado desativada' -Esperado 'Desativada' `
        -Encontrado "Erro: $($_.Exception.Message)" -Status 'ERRO' -Recomendacao 'Verificar manualmente'
}

# --- CHECAGEM 6: Tamanho minimo de senha >= 14 ---
$tamanho = Get-Politica 'MinimumPasswordLength'
Add-Resultado -Id 'PWD-01' -Checagem 'Tamanho minimo de senha' `
    -Esperado '>= 14' -Encontrado "$tamanho" -Status (Get-Status ($tamanho -ge 14)) `
    -Recomendacao 'net accounts /minpwlen:14'

# --- CHECAGEM 7: Bloqueio de conta apos 1 a 5 tentativas erradas ---
$bloqueio = Get-Politica 'LockoutBadCount'
Add-Resultado -Id 'PWD-02' -Checagem 'Limite de tentativas antes do bloqueio' `
    -Esperado '1 a 5' -Encontrado "$bloqueio" -Status (Get-Status ($bloqueio -ge 1 -and $bloqueio -le 5)) `
    -Recomendacao 'net accounts /lockoutthreshold:5'

# --- CHECAGEM 8: Area de Trabalho Remota (RDP) desativada ---
try {
    $rdp = Get-ItemPropertyValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
    Add-Resultado -Id 'NET-02' -Checagem 'RDP desativado' `
        -Esperado '1' -Encontrado "$rdp" -Status (Get-Status ($rdp -eq 1)) `
        -Recomendacao 'Desativar em Configuracoes > Sistema > Area de Trabalho Remota'
} catch {
    Add-Resultado -Id 'NET-02' -Checagem 'RDP desativado' -Esperado '1' `
        -Encontrado 'Chave nao encontrada' -Status 'ERRO' -Recomendacao 'verificar manualmente'
}

# --- CHECAGEM 9: LSASS ---
try {
    $lsa = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction Stop
        Add-Resultado -Id 'SYS-02' -Checagem 'Protecao do LSASS (RunAsPPL)' -Esperado '1' -Encontrado "$lsa" -Status (Get-Status ($lsa -eq 1)) -Recomendacao 'Criar RunAsPPL = 1 em HKLM:\SYSTEM\CurrentControlSet\Control\Lsa e reiniciar'-Recomendacao 'Criar RunAsPPL = 1 em HKLM:\SYSTEM\CurrentControlSet\Control\Lsa e reiniciar'
} catch {
    Add-Resultado -Id 'SYS-02' -Checagem 'Protecao do LSASS (RunAsPPL)' -Esperado '1' -Encontrado 'Nao configurado' -Status 'REPROVADO' -Recomendacao 'Criar RunAsPPL = 1 em HKLM:\SYSTEM\CurrentControlSet\Control\Lsa e reiniciar'
}

Remove-Item $cfg -ErrorAction SilentlyContinue

# ============================================================
# 4. RELATORIO
# ============================================================
$total     = $Resultados.Count
$aprovados = ($Resultados | Where-Object Status -eq 'APROVADO').Count
$nota      = [math]::Round(($aprovados / $total) * 100)

# Na tela
$Resultados | Format-Table ID, Checagem, Encontrado, Status -AutoSize
Write-Host "Pontuacao: $aprovados de $total ($nota%)" -ForegroundColor Cyan

# Arquivos
$data  = Get-Date -Format 'yyyy-MM-dd_HHmm'
$pasta = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$Resultados | ConvertTo-Json | Out-File (Join-Path $pasta "relatorio_$data.json") -Encoding utf8

$css = @'
<style>
 body { font-family: Segoe UI, sans-serif; margin: 32px; background: #f6f7f9; color: #1d1d1f; }
 h1 { margin-bottom: 4px; }
 table { border-collapse: collapse; width: 100%; background: #fff; }
 th, td { padding: 8px 12px; border-bottom: 1px solid #e3e3e3; text-align: left; }
 th { background: #1d1d1f; color: #fff; }
 .ok { color: #1a7f37; font-weight: 600; }
 .falha { color: #cf222e; font-weight: 600; }
 .erro { color: #9a6700; font-weight: 600; }
</style>
'@
$titulo = "<h1>Auditoria de Seguranca - $env:COMPUTERNAME</h1><p>$(Get-Date -Format 'dd/MM/yyyy HH:mm') | Pontuacao: <b>$aprovados de $total ($nota%)</b></p>"

$html = $Resultados | ConvertTo-Html -Head $css -PreContent $titulo -Title 'Auditoria de Seguranca' | Out-String
$html = $html -replace '<td>APROVADO</td>', '<td class="ok">APROVADO</td>' `
              -replace '<td>REPROVADO</td>', '<td class="falha">REPROVADO</td>' `
              -replace '<td>ERRO</td>', '<td class="erro">ERRO</td>'
$html | Out-File (Join-Path $pasta "relatorio_$data.html") -Encoding utf8

Write-Host "Relatorios salvos em: $pasta" -ForegroundColor Green
