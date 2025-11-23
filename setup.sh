#!/usr/bin/env bash
#
# setup-lab.sh
#
# This single script:
#  1) Installs VirtualBox, Vagrant, Ansible if missing (Ubuntu-like OS).
#  2) Creates a multi-VM lab in 'vuln-credit-union-lab/':
#       - DC (promoted from scratch), File Server, Windows 11 workstations (count configurable via W11_COUNT), 1 Win7 Legacy, 1 Web Server
#       - Full AD vulnerabilities, SMB NTLMv2 traffic generation, etc.
#  3) Sequentially boots each VM to reduce memory spikes.
#  4) Leaves you with an isolated, intentionally insecure domain environment.
#
# Requirements:
#   - ~200-300 GB free disk space
#   - ~32 GB RAM if using 2 GB per VM (14 total)
#   - Ubuntu-like distro
#

set -euo pipefail

LAB_DIR="vuln-credit-union-lab"

# Number of Windows 11 workstations to create (default: 2)
W11_COUNT=2
export W11_COUNT

# Dry-run support: set to 1 to skip actions that change the host (vagrant up, installs)
DRY_RUN=0

# Simple CLI parsing for --dry-run and -n/--count
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -n|--count)
      shift
      if [ -n "${1:-}" ]; then
        W11_COUNT="$1"
        export W11_COUNT
        shift
      fi
      ;;
    *)
      echo "[WARN] Unknown argument: $1"
      shift
      ;;
  esac
done

# Basic logging helpers
LOGFILE="$(pwd)/setup.log"
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOGFILE"; }
log_info() { log "[INFO] $*"; }
log_warn() { log "[WARN] $*"; }
log_error() { log "[ERROR] $*"; }

on_error() {
  rc=$?
  log_error "Script failed at line $1 (exit code $rc). Last command: '${BASH_COMMAND:-unknown}'"
  log_error "See $LOGFILE for details. Exiting."
  exit $rc
}
trap 'on_error $LINENO' ERR

# Wrapper to run commands or print them in dry-run mode
run_cmd() {
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] $*"
  else
    log_info "RUN: $*"
    eval "$*"
  fi
}

# Validate W11_COUNT is numeric and in a reasonable range
validate_w11_count() {
  if ! printf '%s' "$W11_COUNT" | grep -Eq '^[0-9]+$'; then
    log_error "W11_COUNT must be a positive integer. Got: '$W11_COUNT'"
    exit 2
  fi
  if [ "$W11_COUNT" -lt 1 ]; then
    log_warn "W11_COUNT < 1; setting to 1"
    W11_COUNT=1
  fi
  if [ "$W11_COUNT" -gt 20 ]; then
    log_warn "W11_COUNT > 20; capping to 20"
    W11_COUNT=20
  fi
  export W11_COUNT
}

# Preflight checks for disk and RAM
preflight_checks() {
  # Check disk (GB)
  req_disk_gb=50
  avail_gb=$(df --output=avail -BG . | tail -1 | tr -dc '0-9') || avail_gb=0
  if [ -n "$avail_gb" ] && [ "$avail_gb" -lt "$req_disk_gb" ]; then
    log_warn "Available disk (${avail_gb}GB) is less than recommended ${req_disk_gb}GB"
  else
    log_info "Disk check OK: ${avail_gb}GB available"
  fi

  # Check RAM (GB)
  req_ram_gb=8
  if [ -r /proc/meminfo ]; then
    mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
    mem_gb=$(( mem_kb / 1024 / 1024 ))
    if [ "$mem_gb" -lt "$req_ram_gb" ]; then
      log_warn "System RAM (${mem_gb}GB) is less than recommended ${req_ram_gb}GB"
    else
      log_info "RAM check OK: ${mem_gb}GB available"
    fi
  else
    log_warn "Unable to read /proc/meminfo to check RAM"
  fi
}

validate_w11_count
preflight_checks

echo "================================================================="
echo " Setting up 'credit union' lab in '$LAB_DIR' - Full code version."
echo "================================================================="
echo "========== (1/6) Starting OS/Dependency Check =========="

###############################################################################
# 1) Check OS / Install Dependencies (Ubuntu-like)
###############################################################################
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "$ID" != "ubuntu" && "$ID_LIKE" != *"ubuntu"* ]]; then
    echo "[WARNING] This script is optimized for Ubuntu-like distributions."
  fi
else
  echo "[WARNING] Could not detect OS. Proceeding as if Ubuntu-like."
fi

log_info "Updating apt and ensuring apt-utils, curl, wget present..."
run_cmd "sudo apt-get update -y"
run_cmd "sudo apt-get install -y apt-utils curl wget"

if ! command -v virtualbox &> /dev/null; then
  log_warn "VirtualBox not found. Installing VirtualBox..."
  run_cmd "sudo apt-get install -y virtualbox"
else
  log_info "VirtualBox already installed."
fi

if ! command -v vagrant &> /dev/null; then
  log_warn "Vagrant not found. Installing Vagrant..."
  run_cmd "sudo apt-get install -y vagrant"
else
  log_info "Vagrant already installed."
fi

if ! command -v ansible &> /dev/null; then
  log_warn "Ansible not found. Installing Ansible..."
  run_cmd "sudo apt-get install -y ansible"
else
  log_info "Ansible already installed."
fi
echo "========== (1/6) OS/Dependency Check Complete =========="


###############################################################################
# 2) Check or add Windows base boxes to Vagrant (optional example)
###############################################################################
echo "=== [2/6] Checking/Adding Vagrant Boxes (start) ==="
declare -a REQUIRED_BOXES=(
  "gusztavvargadr/windows-server-2019"
  "gusztavvargadr/windows-11"
  "opensky/windows-7-professional-sp1-x64"
)
echo "[*] Checking required Windows base boxes..."
for box in "${REQUIRED_BOXES[@]}"; do
  if vagrant box list | grep -q "$box"; then
    echo "   - Found '$box'"
  else
    log_info "   - Box '$box' not found, adding..."
    run_cmd "vagrant box add '$box' --provider virtualbox"
  fi
done
echo "=== [2/6] Checking/Adding Vagrant Boxes (done) ==="

###############################################################################
# 3) Create 'vuln-credit-union-lab' folder if not existing
###############################################################################
echo "=== [3/6] Creating Lab Folder/Files (start) ==="
if [ -d "$LAB_DIR" ]; then
  log_error "'$LAB_DIR' already exists. Exiting to avoid overwriting."
  exit 1
fi

mkdir -p "$LAB_DIR"
log_info "Created directory '$LAB_DIR'. Writing Vagrant and Ansible files..."
echo "=== [3/6] Creating Lab Folder/Files (done) ==="
###############################################################################
# 4) Write Vagrantfile + Ansible structure + full PowerShell scripts
###############################################################################

#############################
# 4A) Vagrantfile
#############################
echo "=== [4/6] Writing Vagrant + Ansible config (start) ==="
cat <<'EOF' > "$LAB_DIR/Vagrantfile"
Vagrant.configure("2") do |config|
  config.vm.provider :virtualbox do |vb|
    vb.gui = false
    vb.memory = 2048    # Minimal memory: 2 GB
    vb.cpus = 2
  end

  network_base_ip = "192.168.56"

  # DC01
  config.vm.define "dc01" do |dc|
    dc.vm.box = "gusztavvargadr/windows-server-2019"
    dc.vm.hostname = "dc01.creditunion.local"
    dc.vm.network :private_network, ip: "#{network_base_ip}.10"

    dc.vm.communicator = "winrm"
    dc.winrm.username = "vagrant"
    dc.winrm.password = "vagrant"
    dc.winrm.transport = :plaintext
    dc.winrm.basic_auth_only = true

    dc.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "ansible/playbook.yml"
      ansible.inventory_path = "ansible/inventory"
      ansible.extra_vars = { domain_name: "creditunion.local" }
      ansible.limit = "dc01"
    end
  end

  # FILE SERVER
  config.vm.define "fs01" do |fs|
    fs.vm.box = "gusztavvargadr/windows-server-2019"
    fs.vm.hostname = "fs01.creditunion.local"
    fs.vm.network :private_network, ip: "#{network_base_ip}.11"

    fs.vm.communicator = "winrm"
    fs.winrm.username = "vagrant"
    fs.winrm.password = "vagrant"
    fs.winrm.transport = :plaintext
    fs.winrm.basic_auth_only = true

    fs.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "ansible/playbook.yml"
      ansible.inventory_path = "ansible/inventory"
      ansible.extra_vars = { domain_name: "creditunion.local" }
      ansible.limit = "fs01"
    end
  end

  # Windows 11 workstations (count controlled via ENV['W11_COUNT'], default 10)
  w11_count = ENV['W11_COUNT'] ? ENV['W11_COUNT'].to_i : 10

  (1..w11_count).each do |i|
    w11_name = "w11-#{format('%02d', i)}"
    w11_ip = 19 + i  # 192.168.56.20..

    config.vm.define w11_name do |win11|
      win11.vm.box = "gusztavvargadr/windows-11"
      win11.vm.hostname = "#{w11_name}.creditunion.local"
      win11.vm.network :private_network, ip: "#{network_base_ip}.#{w11_ip}"

      win11.vm.communicator = "winrm"
      win11.winrm.username = "vagrant"
      win11.winrm.password = "vagrant"
      win11.winrm.transport = :plaintext
      win11.winrm.basic_auth_only = true

      win11.vm.provision "ansible_local" do |ansible|
        ansible.playbook = "ansible/playbook.yml"
        ansible.inventory_path = "ansible/inventory"
        ansible.extra_vars = { domain_name: "creditunion.local" }
        ansible.limit = w11_name
      end
    end
  end

  # WINDOWS 7 LEGACY
  config.vm.define "w7-legacy" do |w7|
    w7.vm.box = "opensky/windows-7-professional-sp1-x64"
    w7.vm.hostname = "w7-legacy.creditunion.local"
    w7.vm.network :private_network, ip: "#{network_base_ip}.30"

    w7.vm.communicator = "winrm"
    w7.winrm.username = "vagrant"
    w7.winrm.password = "vagrant"
    w7.winrm.transport = :plaintext
    w7.winrm.basic_auth_only = true

    w7.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "ansible/playbook.yml"
      ansible.inventory_path = "ansible/inventory"
      ansible.extra_vars = { domain_name: "creditunion.local" }
      ansible.limit = "w7-legacy"
    end
  end

  # WEB SERVER
  config.vm.define "web01" do |web|
    web.vm.box = "gusztavvargadr/windows-server-2019"
    web.vm.hostname = "web01.creditunion.local"
    web.vm.network :private_network, ip: "#{network_base_ip}.40"

    web.vm.communicator = "winrm"
    web.winrm.username = "vagrant"
    web.winrm.password = "vagrant"
    web.winrm.transport = :plaintext
    web.winrm.basic_auth_only = true

    web.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "ansible/playbook.yml"
      ansible.inventory_path = "ansible/inventory"
      ansible.extra_vars = { domain_name: "creditunion.local" }
      ansible.limit = "web01"
    end
  end
end
EOF

#############################
# 4B) Ansible inventory
#############################
mkdir -p "$LAB_DIR/ansible"
cat <<'EOF' > "$LAB_DIR/ansible/inventory"
[dc]
dc01 ansible_host=192.168.56.10 ansible_user=vagrant ansible_password=vagrant ansible_port=5985 ansible_connection=winrm ansible_winrm_server_cert_validation=ignore

[fileservers]
fs01 ansible_host=192.168.56.11 ansible_user=vagrant ansible_password=vagrant ansible_port=5985 ansible_connection=winrm ansible_winrm_server_cert_validation=ignore

[win11workstations]
EOF

for i in $(seq 1 $W11_COUNT); do
  ip=$((19 + i))
  printf "w11-%02d ansible_host=192.168.56.%d ansible_user=vagrant ansible_password=vagrant ansible_port=5985 ansible_connection=winrm ansible_winrm_server_cert_validation=ignore\n" "$i" "$ip" >> "$LAB_DIR/ansible/inventory"
done

cat <<'EOF' >> "$LAB_DIR/ansible/inventory"
[legacy]
w7-legacy ansible_host=192.168.56.30 ansible_user=vagrant ansible_password=vagrant ansible_port=5985 ansible_connection=winrm ansible_winrm_server_cert_validation=ignore

[webserver]
web01 ansible_host=192.168.56.40 ansible_user=vagrant ansible_password=vagrant ansible_port=5985 ansible_connection=winrm ansible_winrm_server_cert_validation=ignore

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF

#############################
# 4C) Ansible playbook
#############################
cat <<'EOF' > "$LAB_DIR/ansible/playbook.yml"
---
- name: Provision Domain Controller
  hosts: dc
  roles:
    - dc

- name: Provision File Server
  hosts: fileservers
  roles:
    - fileserver

- name: Provision Windows 11 Workstations
  hosts: win11workstations
  roles:
    - workstation

- name: Provision Legacy Win7
  hosts: legacy
  roles:
    - legacy

- name: Provision Web Server (IIS)
  hosts: webserver
  roles:
    - webserver
EOF

#############################
# 4D) Roles and PowerShell
#############################
mkdir -p "$LAB_DIR/ansible/roles/dc/tasks"
mkdir -p "$LAB_DIR/ansible/roles/dc/files"
mkdir -p "$LAB_DIR/ansible/roles/fileserver/tasks"
mkdir -p "$LAB_DIR/ansible/roles/fileserver/files"
mkdir -p "$LAB_DIR/ansible/roles/workstation/tasks"
mkdir -p "$LAB_DIR/ansible/roles/workstation/files"
mkdir -p "$LAB_DIR/ansible/roles/legacy/tasks"
mkdir -p "$LAB_DIR/ansible/roles/legacy/files"
mkdir -p "$LAB_DIR/ansible/roles/webserver/tasks"
mkdir -p "$LAB_DIR/ansible/roles/webserver/files"

#
# DC ROLE (main.yml)
#
cat <<'EOF' > "$LAB_DIR/ansible/roles/dc/tasks/main.yml"
---
- name: Copy DC promotion script
  win_copy:
    src: Configure-DCpromote.ps1
    dest: C:\Temp\Configure-DCpromote.ps1

- name: Promote DC if needed
  win_shell: |
    powershell.exe -ExecutionPolicy Bypass -File "C:\\Temp\\Configure-DCpromote.ps1" -DomainName "{{ domain_name }}"
  register: promote_dc

- name: Reboot after promotion if needed
  win_reboot:
    reboot_timeout: 1800
  when: promote_dc.rc == 3010 or promote_dc.stdout | search('REBOOT')

- name: Copy Invoke-VulnAD
  win_copy:
    src: Invoke-VulnAD.ps1
    dest: C:\Temp\Invoke-VulnAD.ps1

- name: Run Invoke-VulnAD
  win_shell: |
    powershell.exe -ExecutionPolicy Bypass -File "C:\\Temp\\Invoke-VulnAD.ps1" -DomainName "{{ domain_name }}" -UsersLimit 120
  register: vuln_ad

- name: Debug output from Invoke-VulnAD
  debug:
    msg: "{{ vuln_ad.stdout }}"
EOF

#
# DC ROLE (Configure-DCpromote.ps1)
#
cat <<'EOF' > "$LAB_DIR/ansible/roles/dc/files/Configure-DCpromote.ps1"
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

Write-Host "[*] Checking if domain '$DomainName' is present..."

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

try {
    $existing = Get-ADDomain $DomainName -ErrorAction Stop
    Write-Host "[+] Domain '$DomainName' found; no promotion needed."
}
catch {
    Write-Host "[!] Domain not found. Installing AD DS..."

    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $DomainName `
        -SafeModeAdministratorPassword (ConvertTo-SecureString 'S@feModePW1' -AsPlainText -Force) `
        -InstallDns `
        -Force

    Write-Host "[*] DC promotion triggered. Reboot needed."
    exit 3010
}
EOF

#
# DC ROLE (Invoke-VulnAD.ps1) - FULL script from conversation
#
cat <<'EOF' > "$LAB_DIR/ansible/roles/dc/files/Invoke-VulnAD.ps1"
param(
    [int]$UsersLimit = 100,
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName
)

##################################################################
# FULL AD Vulnerability Script from conversation - no truncation.
##################################################################

function ShowBanner {
    $banner = @()
    $banner += 'VULN AD - Vulnerable Active Directory (Credit Union Simulation)'
    $banner += 'For Training Purposes Only'
    $banner | ForEach-Object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green','Cyan','Yellow','Gray','White'))
    }
    Write-Host "[*] This environment is intentionally vulnerable. Explore, find hints, and learn."
}

function Write-Good { param($String) Write-Host "`t[+]" $String -ForegroundColor 'Green'}
function Write-Bad  { param($String) Write-Host "`t[-]" $String -ForegroundColor 'Red'}
function Write-Info { param($String) Write-Host "`t[*]" $String -ForegroundColor 'Gray'}

$Global:Spacing = "`t"

# Some of these arrays are extremely long, we replicate them fully:
$Global:HumansNames = @('Aaren','Abigail','Adele','Adriana','Aimee','Alaina','Alexa','Alexis','Alicia','Alison','Allison','Amanda','Amelia','Amy','Andrea','Angela','Angelina','Ann','Anna','Annabelle','Anne','Annie','Ariana','Ariel','Ashley','Audrey','Ava','Barbara','Beatrice','Becky','Belinda','Bella','Bernice','Bertha','Beverly','Briana','Bridget','Camila','Candice','Carla','Carmen','Caroline','Carolyn','Cassandra','Catherine','Cecilia','Celeste','Charlotte','Cheryl','Christina','Christine','Cindy','Claire','Clara','Colleen','Crystal','Daisy','Dana','Danielle','Darlene','Debbie','Deborah','Delia','Denise','Diana','Diane','Dolly','Dolores','Donna','Dora','Dorothy','Eleanor','Elena','Elisa','Elizabeth','Ella','Ellen','Ellie','Emily','Emma','Erica','Erin','Esther','Ethel','Eva','Evelyn','Faith','Fannie','Felicia','Fiona','Florence','Frances','Gabriella','Gail','Georgia','Geraldine','Gina','Gladys','Gloria','Grace','Hailey','Hannah','Harriet','Hazel','Heather','Heidi','Helen','Holly','Ida','Imelda','Irene','Iris','Isabel','Isabella','Ivy','Jackie','Jacqueline','Jade','Jamie','Jane','Janet','Janice','Jean','Jeanette','Jeanne','Jenna','Jennifer','Jessica','Jillian','Joan','Joann','Joanna','Jocelyn','Judy','Julia','Julie','June','Kaitlyn','Karen','Karla','Katherine','Kathleen','Kathryn','Katie','Kay','Kayla','Kelly','Kim','Kimberly','Kristen','Kristin','Lana','Laura','Lauren','Leah','Lena','Leslie','Lillian','Lily','Linda','Lindsay','Lisa','Liz','Lois','Lola','Lorraine','Louise','Lucy','Lydia','Lynn','Mabel','Maddie','Madeline','Madison','Mae','Maggie','Mallory','Marcia','Margaret','Maria','Marian','Marilyn','Marisol','Marjorie','Marsha','Martha','Mary','Matilda','Maureen','Megan','Melanie','Melinda','Melissa','Michelle','Mildred','Molly','Monica','Nadia','Nancy','Naomi','Natalie','Natasha','Nicole','Nina','Noelle','Nora','Norma','Olga','Olivia','Opal','Pam','Pamela','Patricia','Paula','Pauline','Pearl','Peggy','Penelope','Phoebe','Polly','Priscilla','Rachel','Rebecca','Regina','Renee','Rhonda','Rita','Robin','Rosa','Rose','Rosemary','Ruby','Ruth','Sabrina','Sadie','Sally','Samantha','Sandra','Sara','Sarah','Selena','Shannon','Sharon','Sheila','Shelby','Sherry','Shirley','Sofia','Stacy','Stella','Stephanie','Sue','Susan','Suzanne','Sylvia','Tabitha','Tamara','Tanya','Tara','Teresa','Theresa','Tiffany','Tina','Tracy','Valerie','Vanessa','Vera','Veronica','Vicki','Victoria','Virginia','Vivian','Wanda','Wendy','Yolanda','Yvonne','Zoe','Zelda')

$Global:BadPasswords = @('Bank123!','Money2024!','Credit123','Loan456','123123','baseball','abc123','football','monkey','letmein','iloveyou','password','ncc1701','changeme','1234','qwerty','michael','welcome','carlos','princess','summer','coffee','pookie')
$Global:HighGroups = @('Domain Admins', 'IT Administrators', 'Executives')
$Global:MidGroups = @('Loan Officers', 'Finance Managers')
$Global:NormalGroups = @('Customer Service', 'Account Representatives', 'Tellers')
$Global:BadACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','Self','WriteProperty')
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver','http_svc,httpserver','exchange_svc,exserver')
$Global:CreatedUsers = @();
$Global:AllObjects = @();
$Global:Domain = ""

function VulnAD-GetRandom {
    Param([array]$InputList)
    return Get-Random -InputObject $InputList
}

function VulnAD-AddADUser {
    Param([int]$limit = 1)
    Add-Type -AssemblyName System.Web
    for ($i=1; $i -le $limit; $i++) {
        $firstname = (VulnAD-GetRandom -InputList $Global:HumansNames)
        $lastname = (VulnAD-GetRandom -InputList $Global:HumansNames)
        $SamAccountName = ("{0}.{1}" -f $firstname, $lastname).ToLower()
        $principalname = "{0}.{1}" -f $firstname, $lastname
        $generated_password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
        Write-Info "Creating $SamAccountName User"
        Try {
            New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName "$principalname@$Global:Domain" -AccountPassword (ConvertTo-SecureString $generated_password -AsPlainText -Force) -PassThru | Enable-ADAccount
        } Catch {}
        $Global:CreatedUsers += $SamAccountName
    }

    # Add incremental password pattern hints to a few users
    for ($j=1; $j -le 3; $j++) {
        $selectedUser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        Set-ADUser $selectedUser -Description "Password Pattern: MonthYear! Example: July2024!"
        Write-Info "Added incremental password pattern hint to $selectedUser"
    }
}

function VulnAD-AddADGroup {
    Param([array]$GroupList)
    foreach ($group in $GroupList) {
        Write-Info "Creating $group Group"
        Try { New-ADGroup -Name $group -GroupScope Global } Catch {}
        for ($i=1; $i -le (Get-Random -Maximum 20); $i++) {
            $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
            Write-Info "Adding $randomuser to $group"
            Try { Add-ADGroupMember -Identity $group -Members $randomuser } Catch {}
        }
        $Global:AllObjects += $group
    }
}

function VulnAD-AddACL {
    [CmdletBinding()]
    param(
        [string]$Destination,
        [System.Security.Principal.IdentityReference]$Source,
        [string]$Rights
    )
    $ADObject = [ADSI]("LDAP://" + $Destination)
    $identity = $Source
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type,$inheritanceType)
    $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
    $ADObject.psbase.CommitChanges()
}

function VulnAD-BadAcls {
    Write-Info "Simulating bad ACL configurations..."
    foreach ($abuse in $Global:BadACL) {
        $ngroup = VulnAD-GetRandom -InputList $Global:NormalGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $mgroup
        $SrcGroup = Get-ADGroup -Identity $ngroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
    }
    foreach ($abuse in $Global:BadACL) {
        $hgroup = VulnAD-GetRandom -InputList $Global:HighGroups
        $mgroup = VulnAD-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        VulnAD-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
    }
    for ($i=1; $i -le (Get-Random -Maximum 25); $i++) {
        $abuse = (VulnAD-GetRandom -InputList $Global:BadACL)
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = VulnAD-GetRandom -InputList $Global:AllObjects
        if ((Get-Random -Maximum 2)) {
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        } else {
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        VulnAD-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse
    }
}

function VulnAD-Kerberoasting {
    Write-Info "Configuring Kerberoastable service accounts..."
    $selected_service = (VulnAD-GetRandom -InputList $Global:ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0]
    $spn = $selected_service.split(',')[1]
    $password = VulnAD-GetRandom -InputList $Global:BadPasswords
    Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -RestrictToSingleComputer -PassThru } Catch {}
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0]
            $spn = $sv.split(',')[1]
            $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
            Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru } Catch {}
        }
    }
}

function VulnAD-ASREPRoasting {
    Write-Info "Configuring AS-REP roasting targets..."
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
    }
}

function VulnAD-DnsAdmins {
    Write-Info "Adding low-priv users to DnsAdmins..."
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
    }
    $randomg = (VulnAD-GetRandom -InputList $Global:MidGroups)
    Add-ADGroupMember -Identity "DnsAdmins" -Members $randomg
}

function VulnAD-PwdInObjectDescription {
    Write-Info "Storing random passwords in user descriptions..."
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $randomuser = VulnAD-GetRandom -InputList $Global:CreatedUsers
        $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "User Password: $password"
    }
}

function VulnAD-DefaultPassword {
    Write-Info "Assigning known default password..."
    for ($i=1; $i -le (Get-Random -Maximum 5); $i++) {
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        $password = "Changeme123!"
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "New User, DefaultPassword"
        Set-AdUser $randomuser -ChangePasswordAtLogon $true
    }
}

function VulnAD-PasswordSpraying {
    Write-Info "Same password for multiple accounts (Spraying scenario)..."
    $same_password = "ncc1701"
    for ($i=1; $i -le (Get-Random -Maximum 12); $i++) {
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $same_password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "Shared User"
    }
}

function VulnAD-DCSync {
    Write-Info "Granting DCSync rights to random low-priv users..."
    for ($i=1; $i -le (Get-Random -Maximum 6); $i++) {
        $ADObject = [ADSI]("LDAP://" + (Get-ADDomain $Global:Domain).DistinguishedName)
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        $sid = (Get-ADUser -Identity $randomuser).sid

        $objectGuidGetChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 89e95b76-444d-4c62-991a-0facbeda640c
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)
        $ADObject.psbase.CommitChanges()

        Set-ADUser $randomuser -Description "Replication Account"
    }
}

function VulnAD-DisableSMBSigning {
    Write-Info "Disabling SMB signing..."
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm:$false -Force
}

function VulnAD-AddGroupPolicyMisconfiguration {
    Write-Info "Creating misconfigured GPO..."
    Try {
        $gpoName = "VulnerableGPO"
        New-GPO -Name $gpoName -Domain $Global:Domain | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\TestVuln" -ValueName "Hint" -Type String -Value "Use creds: financeuser / Finance@2024!"
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\TestVuln" -ValueName "PatternReminder" -Type String -Value "Remember patterns: MonthYear!, CFO2024!"
    } Catch {
        Write-Bad "Failed to create/modify GPO: $_"
    }
}

function VulnAD-AddCFOManager {
    Write-Info "Creating CFO Manager with predictable password..."
    Try {
        $password = "CFO2024!"
        New-ADUser -Name "CFO Manager" -SamAccountName "cfo.manager" -UserPrincipalName "cfo.manager@$Global:Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
        Set-ADUser "cfo.manager" -Description "VIP User - High Value Target"
        $Global:CreatedUsers += "cfo.manager"
    } Catch {
        Write-Bad "Failed to create CFO user."
    }
}

function VulnAD-AddHintsAndShares {
    Write-Info "Creating hint files in SYSVOL and a honey share..."
    $sysvolPath = "\\$Global:Domain\SYSVOL\$Global:Domain\scripts"
    if (!(Test-Path $sysvolPath)) { New-Item -ItemType Directory -Path $sysvolPath -Force | Out-Null }

    $hintText = @"
*** TRAINING HINTS ***

- Check user descriptions, GPO registry values, and SYSVOL for password hints.
- Weak/default passwords like 'Changeme123!' and 'ncc1701' are in use.
- CFO Manager password: CFO2024!
- SMB signing off -> Consider MITM attacks.
- AS-REP roast, Kerberoast, DCSync misconfigurations are present.
- HoneyShare on DC: Check for suspicious files.

Happy Hunting!
"@
    $hintFile = Join-Path $sysvolPath "VulnReadme.txt"
    $hintText | Out-File $hintFile

    $incidentLog = @"
INCIDENT REPORT - INTERNAL USE ONLY

Date: $(Get-Date)
Detected multiple failed login attempts on user account: loan.officer
Failed attempts used common passwords like 'Money2024!' and 'Credit123'.
Network team suspects a password spray attack. No mitigation taken yet.

Reminder: CFO Manager credentials might be too predictable. Check known patterns!
"@
    $incidentFile = Join-Path $sysvolPath "IncidentReport.log"
    $incidentLog | Out-File $incidentFile
    Write-Info "Added a fake Incident Report log in SYSVOL."

    $honeySharePath = "C:\HoneyData"
    if (!(Test-Path $honeySharePath)) { New-Item -ItemType Directory $honeySharePath | Out-Null }

    $fakeSalaries = @"
Name,Role,Annual Salary (USD)
Jane Doe,Chief Financial Officer,250000
Mark Allen,Chief Operations Officer,230000
Lisa Wright,Head of Lending,190000
Samuel Lee,Director of IT,180000
Rebecca Stone,Head of HR,175000
[REDACTED INFO - Use CFO Manager Account for details]
"@
    $fakeSalaries | Out-File (Join-Path $honeySharePath "Executive_Salaries_2024.xlsx")

    $backupScript = @"
# Fake backup script
# Hardcoded creds (bad practice!)
\$Cred = New-Object System.Management.Automation.PSCredential('backup.user@creditunion.local',(ConvertTo-SecureString 'Backup2024!' -AsPlainText -Force))
Write-Host 'Starting backup with user backup.user@creditunion.local and password Backup2024!'
"@
    $backupScriptFile = Join-Path $honeySharePath "DailyBackup.ps1"
    $backupScript | Out-File $backupScriptFile
    Write-Info "Added a DailyBackup.ps1 script with hardcoded creds in HoneyShare."

    New-SmbShare -Name "HoneyShare" -Path $honeySharePath -FullAccess "Everyone" -Confirm:$false | Out-Null
    Write-Info "HoneyShare created with fake Executive salaries and backup script."
}

function VulnAD-AddSuspiciousScheduledTask {
    Write-Info "Adding a suspicious scheduled task on the DC..."
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "'#TODO: Use creds: FinanceUser / Finance2024!'"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

    Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -TaskName "FinanceDataSync" -Description "Syncs finance data daily. Credentials: FinanceUser / Finance2024!" | Out-Null

    Write-Info "Suspicious scheduled task created with credential hints."
}

# In conversation, we had all these subfunctions spelled out. Insert them fully here.

function Invoke-VulnAD {
    ShowBanner
    $Global:Domain = $DomainName

    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -LockoutThreshold 2 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4

    VulnAD-AddADUser -limit $UsersLimit
    Write-Good "Users Created"

    VulnAD-AddADGroup -GroupList $Global:HighGroups
    VulnAD-AddADGroup -GroupList $Global:MidGroups
    VulnAD-AddADGroup -GroupList $Global:NormalGroups
    Write-Good "Groups Created"

    VulnAD-BadAcls
    Write-Good "BadACL Done"

    VulnAD-Kerberoasting
    Write-Good "Kerberoasting Done"

    VulnAD-ASREPRoasting
    Write-Good "AS-REPRoasting Done"

    VulnAD-DnsAdmins
    Write-Good "DnsAdmins Done"

    VulnAD-PwdInObjectDescription
    Write-Good "Password In Object Description Done"

    VulnAD-DefaultPassword
    Write-Good "Default Password Done"

    VulnAD-PasswordSpraying
    Write-Good "Password Spraying Done"

    VulnAD-DCSync
    Write-Good "DCSync Done"

    VulnAD-DisableSMBSigning
    Write-Good "SMB Signing Disabled"

    VulnAD-AddGroupPolicyMisconfiguration
    Write-Good "Misconfigured GPO Added"

    VulnAD-AddCFOManager
    Write-Good "CFO Manager Created"

    VulnAD-AddHintsAndShares
    Write-Good "Hints & Honey Share Created"

    VulnAD-AddSuspiciousScheduledTask
    Write-Good "Suspicious Scheduled Task Created"

    Write-Host "`n`t[INFO] Setup Complete. Trainees can now explore, enumerate, and learn."
}

# End of full script
EOF

#############################
# FILESERVER ROLE
#############################
cat <<'EOF' > "$LAB_DIR/ansible/roles/fileserver/tasks/main.yml"
---
- name: Copy File Server config script
  win_copy:
    src: Configure-FileServer.ps1
    dest: C:\Temp\Configure-FileServer.ps1

- name: Run File Server config
  win_shell: |
    powershell.exe -ExecutionPolicy Bypass -File "C:\\Temp\\Configure-FileServer.ps1" -DomainName "{{ domain_name }}"
EOF

cat <<'EOF' > "$LAB_DIR/ansible/roles/fileserver/files/Configure-FileServer.ps1"
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

Write-Host "[*] Configuring File Server ($env:COMPUTERNAME)..."

$SharePath = "C:\FinData"
if (!(Test-Path $SharePath)) {
    New-Item -ItemType Directory -Path $SharePath | Out-Null
}
Write-Host "[*] Creating FinDataShare with weak permissions..."
New-SmbShare -Name "FinDataShare" -Path $SharePath -FullAccess "Everyone" -Confirm:$false | Out-Null

$loanApprovals = @"
LOAN APPROVALS - 2024 Q1

Customer: John Smith
Requested: \$50,000 - Status: Denied
Customer: Sarah Johnson
Requested: \$15,000 - Status: Approved
Customer: Carlos Perez
Requested: \$200,000 - Pending CFO

Note: CFO might override.
"@
$loanApprovals | Out-File (Join-Path $SharePath "LoanApprovals2024.txt")

Write-Host "[*] Disabling Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Write-Host "[+] File Server configuration complete."
EOF

#############################
# WORKSTATION ROLE
#############################
cat <<'EOF' > "$LAB_DIR/ansible/roles/workstation/tasks/main.yml"
---
- name: Copy Workstation script
  win_copy:
    src: Configure-Workstation.ps1
    dest: C:\Temp\Configure-Workstation.ps1

- name: Run Workstation config
  win_shell: |
    powershell.exe -ExecutionPolicy Bypass -File "C:\\Temp\\Configure-Workstation.ps1" -DomainName "{{ domain_name }}" -DomainUsername "Administrator" -DomainPassword "P@ssw0rd" -TargetSharePath "\\dc01.creditunion.local\\HoneyShare"
EOF

cat <<'EOF' > "$LAB_DIR/ansible/roles/workstation/files/Configure-Workstation.ps1"

param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    [Parameter(Mandatory=$true)]
    [string]$DomainUsername,
    [Parameter(Mandatory=$true)]
    [string]$DomainPassword,
    [Parameter(Mandatory=$true)]
    [string]$TargetSharePath
)

Write-Host "[*] Starting Workstation Configuration..." -ForegroundColor Cyan

# Function to generate random weak passwords
function Generate-WeakPassword {
    $weakPasswords = @('Password123', '12345678', 'qwerty123', 'Welcome1', 'Admin2024', 'Changeme!')
    return Get-Random -InputObject $weakPasswords
}

# Function to check if the computer is domain-joined
function Is-DomainJoined {
    return ([bool]([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() -ne $null))
}

# Step 1: Ensure the machine is domain-joined
if (Is-DomainJoined) {
    Write-Host "[+] Workstation is already joined to domain '$DomainName'." -ForegroundColor Green
} else {
    Write-Host "[*] Attempting to join the domain '$DomainName'..." -ForegroundColor Cyan
    try {
        Add-Computer -DomainName $DomainName -Credential (New-Object System.Management.Automation.PSCredential ($DomainUsername, (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))) -Force
        Restart-Computer -Force
    } catch {
        Write-Host "[-] Failed to join the domain '$DomainName': $_" -ForegroundColor Red
        exit 1
    }
}

# Step 2: Create random local users
function Create-RandomLocalUsers {
    Write-Host "[*] Adding random local users..." -ForegroundColor Cyan
    $userCount = Get-Random -Minimum 3 -Maximum 7
    for ($i = 1; $i -le $userCount; $i++) {
        $username = "User$((Get-Random -Minimum 1000 -Maximum 9999))"
        $password = Generate-WeakPassword
        try {
            # Create local user
            New-LocalUser -Name $username -Password (ConvertTo-SecureString $password -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword -Description "Password: $password"
            Write-Host "[+] Added local user: $username with password: $password" -ForegroundColor Green

            # Optionally add some users to the local Administrators group
            if ((Get-Random -Minimum 0 -Maximum 1) -eq 1) {
                Add-LocalGroupMember -Group "Administrators" -Member $username
                Write-Host "[!] $username added to local Administrators group." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[-] Failed to create user '$username': $_" -ForegroundColor Red
        }
    }
}

Create-RandomLocalUsers

# Step 3: Configure the scheduled task
Write-Host "[*] Creating scheduled task to access HoneyShare..." -ForegroundColor Cyan
try {
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "Test-Path '$TargetSharePath'"
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration ([TimeSpan]::FromDays(365))
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    if (!(Get-ScheduledTask -TaskName "CheckHoneyShare" -ErrorAction SilentlyContinue)) {
        Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -TaskName "CheckHoneyShare" -Description "Periodically attempt to access a share" | Out-Null
        Write-Host "[+] Scheduled task 'CheckHoneyShare' created." -ForegroundColor Green
    } else {
        Write-Host "[+] Scheduled task 'CheckHoneyShare' already exists. Skipping." -ForegroundColor Green
    }
} catch {
    Write-Host "[-] Failed to create scheduled task: $_" -ForegroundColor Red
}

Write-Host "[*] Workstation configuration complete." -ForegroundColor Green
EOF

#############################
# LEGACY ROLE
#############################
cat <<'EOF' > "$LAB_DIR/ansible/roles/legacy/tasks/main.yml"
---
- name: Copy Legacy script
  win_copy:
    src: Configure-LegacyVM.ps1
    dest: C:\Temp\Configure-LegacyVM.ps1

- name: Run Legacy config
  win_shell: |
    powershell.exe -ExecutionPolicy Bypass -File "C:\\Temp\\Configure-LegacyVM.ps1" -DomainName "{{ domain_name }}" -DomainUsername "Administrator" -DomainPassword "P@ssw0rd"
EOF

cat <<'EOF' > "$LAB_DIR/ansible/roles/legacy/files/Configure-LegacyVM.ps1"
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    [Parameter(Mandatory=$true)]
    [string]$DomainUsername,
    [Parameter(Mandatory=$true)]
    [string]$DomainPassword
)

Write-Host "[*] Configuring Win7 Legacy VM ($env:COMPUTERNAME)..."

try {
    Write-Host "[*] Re-enabling WDigest..."
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -PropertyType DWORD -Force | Out-Null

    Write-Host "[*] Lowering LMCompatibilityLevel..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 1
}
catch {
    Write-Host "[-] Could not re-enable WDigest or set LMCompatibility: $_"
}

Write-Host "[*] Joining domain: $DomainName..."
Add-Computer -DomainName $DomainName -Credential (New-Object System.Management.Automation.PSCredential($DomainUsername, (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))) -Force
Restart-Computer -Force
EOF

#############################
# WEB SERVER ROLE
#############################
cat <<'EOF' > "$LAB_DIR/ansible/roles/webserver/tasks/main.yml"
---
- name: Copy Web Server script
  win_copy:
    src: Configure-WebServer.ps1
    dest: C:\Temp\Configure-WebServer.ps1

- name: Run Web Server config
  win_shell: |
    powershell.exe -ExecutionPolicy Bypass -File "C:\\Temp\\Configure-WebServer.ps1" -DomainName "{{ domain_name }}" -DomainUsername "Administrator" -DomainPassword "P@ssw0rd"
EOF

cat <<'EOF' > "$LAB_DIR/ansible/roles/webserver/files/Configure-WebServer.ps1"
param(
[Parameter(Mandatory = $true)]
[string]$DomainName,
[Parameter(Mandatory = $true)]
[string]$DomainUsername,
[Parameter(Mandatory = $true)]
[string]$DomainPassword
)

# Utility function for logging
function Write-Log {
param (
[string]$Message,
[ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
[string]$Level
)
$color = switch ($Level) {
"INFO"    { "Cyan" }
"SUCCESS" { "Green" }
"WARNING" { "Yellow" }
"ERROR"   { "Red" }
}
Write-Host "[$Level] $Message" -ForegroundColor $color
}

# Validate Active Directory module
function Validate-ADModule {
Write-Log "Validating Active Directory module..." "INFO"
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
Write-Log "Active Directory module is not installed. Attempting to install RSAT: Active Directory tools..." "WARNING"
Try {
# Fallback to DISM for RSAT installation
Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:RSAT-AD-PowerShell /All /NoRestart" -Wait -NoNewWindow
if (Get-Module -ListAvailable -Name ActiveDirectory) {
Write-Log "Successfully installed Active Directory module." "SUCCESS"
} else {
Write-Log "Failed to install Active Directory module." "ERROR"
return $false
}
} Catch {
Write-Log "Failed to install IIS. Error: $" "ERROR"
return $false
}
} else {
Write-Log "Active Directory module is available." "SUCCESS"
}
return $true
}

# Validate IIS installation
function Validate-IIS {
Write-Log "Validating IIS installation..." "INFO"
$iisInstalled = (Get-WindowsOptionalFeature -Online | Where-Object { $.FeatureName -eq "IIS-WebServerRole" }).State -eq "Enabled"
if (-not $iisInstalled) {
Write-Log "IIS (Web-Server) is not installed. Attempting to install IIS..." "WARNING"
Try {
# Fallback to DISM for IIS installation
Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-WebServerRole /All /NoRestart" -Wait -NoNewWindow
$iisInstalled = (Get-WindowsOptionalFeature -Online | Where-Object { $.FeatureName -eq "IIS-WebServerRole" }).State -eq "Enabled"
if ($iisInstalled) {
Write-Log "Successfully installed IIS." "SUCCESS"
} else {
Write-Log "Failed to install IIS." "ERROR"
return $false
}
} Catch {
Write-Log "Failed to install IIS. Error: $" "ERROR"
return $false
}
} else {
Write-Log "IIS is already installed." "SUCCESS"
}
return $true
}

# Join domain if not already joined
function Ensure-DomainJoin {
Write-Log "Validating domain membership..." "INFO"
$domainInfo = (Get-WmiObject -Class Win32_ComputerSystem).Domain
if ($domainInfo -eq $DomainName) {
Write-Log "Machine is already joined to the domain '$DomainName'." "SUCCESS"
return $true
}

Write-Log "Machine is not joined to the domain. Attempting to join..." "WARNING"
Try {
Add-Computer -DomainName $DomainName -Credential (New-Object System.Management.Automation.PSCredential("$DomainName\$DomainUsername", (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))) -Force -Restart
Write-Log "Successfully joined the domain '$DomainName'." "SUCCESS"
return $true
} Catch {
Write-Log "Failed to join the domain '$DomainName'. Error: $" "ERROR"
return $false
}
}

# Create basic webpage
function Create-BasicWebPage {
Write-Log "Creating a basic admin webpage..." "INFO"
$webRoot = "C:\inetpub\wwwroot"
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
<title>Admin Portal</title>
</head>
<body>
<h1>Welcome to Admin Portal</h1>
<form action="/login" method="post">
<label for="username">Username:</label>
<input type="text" id="username" name="username"><br><br>
<label for="password">Password:</label>
<input type="password" id="password" name="password"><br><br>
<input type="submit" value="Login">
</form>
</body>
</html>
"@
Try {
$htmlContent | Set-Content -Path "$webRoot\index.html" -Force
Write-Log "Successfully created admin webpage." "SUCCESS"
} Catch {
Write-Log "Failed to create admin webpage. Error: $" "ERROR"
}
}

# Main execution flow
Write-Log "Starting web server configuration..." "INFO"
if (-not (Validate-ADModule)) { exit 1 }
if (-not (Validate-IIS)) { exit 1 }
if (-not (Ensure-DomainJoin)) { exit 1 }
Create-BasicWebPage
Write-Log "Web server configuration complete." "SUCCESS"
EOF

echo "[*] Finished writing all configuration files."
echo "=== [4/6] Writing Vagrant + Ansible config (done) ==="
###############################################################################
# 5) Spin up machines in sequence
###############################################################################
echo "=== [5/6] Spinning up VMs in sequence (done) ==="
cd "$LAB_DIR"
echo "[*] Now in $(pwd). Bringing up each VM in order..."

echo "==> Starting dc01 (Domain Controller)..."
run_cmd "vagrant up dc01"

echo "==> Starting fs01 (File Server)..."
run_cmd "vagrant up fs01"

for i in $(seq 1 $W11_COUNT); do
  VM_NAME="w11-$(printf '%02d' $i)"
  echo "==> Starting $VM_NAME (Windows 11)..."
  run_cmd "vagrant up '$VM_NAME'"
done

echo "==> Starting w7-legacy (Windows 7)..."
run_cmd "vagrant up w7-legacy"

echo "==> Starting web01 (Web Server)..."
run_cmd "vagrant up web01"
echo "=== [5/6] Spinning up VMs in sequence (done) ==="
#######################################
# STAGE 6: COMPLETION
#######################################
echo "[*] All machines have been provisioned sequentially."
echo "[*] The 'credit union' lab is now up and running."
echo "[*] Summary: Domain Controller, File Server, ${W11_COUNT} Win11, 1 Win7, 1 WebServer."
echo "    Vulnerable AD config applied; Win11 sends periodic NTLMv2 SMB traffic."
echo "=== [6/6] Lab environment is fully ready. ==="