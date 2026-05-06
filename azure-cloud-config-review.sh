#!/usr/bin/env bash
###############################################################################
#                                                                             #
#   AZURE CLOUD CONFIGURATION REVIEW - AUTOMATED ASSESSMENT SCRIPT           #
#   ---------------------------------------------------------------          #
#   CSA CCM · CIS Benchmarks for Azure · MITRE ATT&CK for Cloud ·            #
#   Azure Well-Architected Framework Security Pillar                          #
#                                                                             #
#   Required Permissions (Azure Managed Roles):                               #
#     - Reader + Security Reader on each in-scope Subscription                #
#     - Global Reader in Entra ID                                             #
#     - Microsoft Graph API: User.Read.All, Policy.Read.All,                  #
#       Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.All        #
#                                                                             #
#   Usage: ./azure-cloud-config-review.sh                                     #
#                                                                             #
###############################################################################

# ---------- DO NOT use `set -e` ----------
# Many Azure API calls legitimately fail (service not enabled, region
# disabled, permissions scoped, etc.) and the assessment must continue.
set -o pipefail

###############################################################################
# GLOBAL VARIABLES & COLOR CODES
###############################################################################

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

readonly SCRIPT_VERSION="1.0.1-kali-az-fix"
readonly SCRIPT_NAME="Azure Cloud Configuration Review"

TENANT_ID=""
APP_ID=""
CLIENT_SECRET=""
SUBSCRIPTION_IDS=()
CLIENT_NAME=""
OUTPUT_DIR=""
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OS=""

FINDINGS_CRITICAL=0
FINDINGS_HIGH=0
FINDINGS_MEDIUM=0
FINDINGS_INFO=0

# Format: SEVERITY|MODULE|TECHNIQUE|MESSAGE|TIMESTAMP
FINDINGS_LOG=""
CURRENT_MODULE="INIT"

###############################################################################
# HELPER / UI FUNCTIONS
###############################################################################

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
   ___  ____  __  ________   ______             _____                _
  / _ |/_  / / / / // __  /  / ____/___  ____  / __(_)___ _   ____ _(_)__ _      __
 / __ | / / / /_/ // /_/ /  / /   / __ \/ __ \/ /_/ / __ `/  / ___/ _ \ | / / _ \/  \ /
/_/ |_|/_/  \____/ \____/   \____/\____/_/ /_/_/ /_/\__, /  /_/   \__/\_/_/\___/_/\_\
                                                    /____/
     CLOUD CONFIGURATION REVIEW  |  CSA CCM · CIS · MITRE ATT&CK · Well-Architected
EOF
    echo -e "${NC}"
    echo -e "${CYAN}${BOLD}==============================================================================${NC}"
    echo -e "  ${BOLD}Script:${NC}      $SCRIPT_NAME"
    echo -e "  ${BOLD}Version:${NC}     $SCRIPT_VERSION"
    echo -e "  ${BOLD}Date:${NC}        $(date)"
    echo -e "${CYAN}${BOLD}==============================================================================${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}==============================================================================${NC}"
    echo ""
}

print_subsection() {
    echo ""
    echo -e "${MAGENTA}${BOLD}[>] $1${NC}"
    echo -e "${MAGENTA}------------------------------------------------------------------------------${NC}"
}

print_success() { echo -e "  ${GREEN}[✓]${NC} $1"; }
print_warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "  ${RED}[✗]${NC} $1"; }
print_info()    { echo -e "  ${CYAN}[i]${NC} $1"; }

print_finding_critical() {
    echo -e "  ${RED}${BOLD}[🚨 CRITICAL]${NC} ${RED}$1${NC}"
    ((FINDINGS_CRITICAL++))
    [[ -n "$FINDINGS_LOG" ]] && echo "CRITICAL|${CURRENT_MODULE}||$1|$(date +%H:%M:%S)" >> "$FINDINGS_LOG"
}

print_finding_high() {
    echo -e "  ${RED}[⚠ HIGH]${NC} $1"
    ((FINDINGS_HIGH++))
    [[ -n "$FINDINGS_LOG" ]] && echo "HIGH|${CURRENT_MODULE}||$1|$(date +%H:%M:%S)" >> "$FINDINGS_LOG"
}

print_finding_medium() {
    echo -e "  ${YELLOW}[▲ MEDIUM]${NC} $1"
    ((FINDINGS_MEDIUM++))
    [[ -n "$FINDINGS_LOG" ]] && echo "MEDIUM|${CURRENT_MODULE}||$1|$(date +%H:%M:%S)" >> "$FINDINGS_LOG"
}

print_finding_info() {
    echo -e "  ${CYAN}[ℹ INFO]${NC} $1"
    ((FINDINGS_INFO++))
    [[ -n "$FINDINGS_LOG" ]] && echo "INFO|${CURRENT_MODULE}||$1|$(date +%H:%M:%S)" >> "$FINDINGS_LOG"
}

print_finding_with_technique() {
    local severity="$1"
    local technique="$2"
    local message="$3"
    local tagged_msg="[${technique}] ${message}"
    case "${severity,,}" in
        critical)
            echo -e "  ${RED}${BOLD}[🚨 CRITICAL]${NC} ${RED}${tagged_msg}${NC}"
            ((FINDINGS_CRITICAL++))
            ;;
        high)
            echo -e "  ${RED}[⚠ HIGH]${NC} ${tagged_msg}"
            ((FINDINGS_HIGH++))
            ;;
        medium)
            echo -e "  ${YELLOW}[▲ MEDIUM]${NC} ${tagged_msg}"
            ((FINDINGS_MEDIUM++))
            ;;
        info)
            echo -e "  ${CYAN}[ℹ INFO]${NC} ${tagged_msg}"
            ((FINDINGS_INFO++))
            ;;
    esac
    [[ -n "$FINDINGS_LOG" ]] && \
        echo "${severity^^}|${CURRENT_MODULE}|${technique}|${message}|$(date +%H:%M:%S)" >> "$FINDINGS_LOG"
}

# Safe Azure CLI wrapper — never aborts on API failure
az_safe() {
    az "$@" --output json 2>/dev/null || echo "{}"
}

az_safe_query() {
    # az_safe_query <resource_cmd_args...> --query <jmesquery>
    az "$@" --output json 2>/dev/null || echo "[]"
}

# Run a Graph API call via az rest
graph_get() {
    local url="$1"
    az rest --method GET --url "$url" --output json 2>/dev/null || echo "{}"
}

log_cmd() {
    local logfile="$1"
    shift
    echo "# Command: $*" >> "$logfile"
    echo "# Executed: $(date)" >> "$logfile"
    "$@" >> "$logfile" 2>&1 || true
    echo "" >> "$logfile"
}

###############################################################################
# DEPENDENCY MANAGEMENT
###############################################################################

check_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        if ! command -v brew &>/dev/null; then
            print_error "Homebrew is not installed. Install it from https://brew.sh first."
            exit 1
        fi
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS="redhat"
    else
        OS="unknown"
        print_warn "Unsupported OS detected. Manual dependency installation may be required."
    fi
    print_info "Detected OS: $OS"
}

install_package() {
    local pkg="$1"
    case "$OS" in
        macos)   brew install "$pkg" ;;
        debian)  sudo apt-get install -y "$pkg" ;;
        redhat)  sudo yum install -y "$pkg" ;;
        *) print_error "Please install '$pkg' manually."; return 1 ;;
    esac
}

check_dependencies() {
    print_section "STEP 1: DEPENDENCY CHECK & INSTALLATION"

    check_os

    local core_tools=(git curl jq python3 pip3 unzip)
    for tool in "${core_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            print_success "$tool is installed"
        else
            print_warn "$tool is NOT installed — attempting to install..."
            if [[ "$tool" == "pip3" ]]; then
                install_package "python3-pip"
            else
                install_package "$tool"
            fi
        fi
    done

    # Azure CLI
    if command -v az &>/dev/null; then
        print_success "Azure CLI is installed ($(az version --output json 2>/dev/null | jq -r '."azure-cli"' 2>/dev/null || echo 'unknown'))"
    else
        print_warn "Azure CLI not found — installing..."
        if [[ "$OS" == "macos" ]]; then
            brew install azure-cli
        elif [[ "$OS" == "debian" ]]; then
            # Kali is Debian-derived, but Microsoft's Azure CLI installer does not
            # always recognize Kali's rolling distro codename. Force the Debian
            # bookworm package repo on Kali, then fall back to the distro package.
            if [[ -f /etc/os-release ]] && grep -qi '^ID=kali' /etc/os-release; then
                print_warn "Kali detected — forcing Azure CLI installer to use Debian bookworm repo"
                if ! curl -sL https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=bookworm bash; then
                    print_warn "Microsoft Azure CLI installer failed on Kali — trying apt package fallback"
                    sudo apt-get update && sudo apt-get install -y azure-cli
                fi
            else
                curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
            fi
        else
            print_error "Please install Azure CLI manually: https://learn.microsoft.com/cli/azure/install-azure-cli"
            exit 1
        fi
    fi

    # Hard validation so dependency failures are not mislabeled as authentication failures.
    if ! command -v az &>/dev/null; then
        print_error "Azure CLI installation failed — 'az' is not available in PATH. Install Azure CLI manually, then rerun this script."
        exit 1
    fi

    print_success "Azure CLI is available ($(az version --output json 2>/dev/null | jq -r '."azure-cli"' 2>/dev/null || echo 'unknown'))"

    # Docker (for Prowler)
    if command -v docker &>/dev/null; then
        print_success "Docker is installed"
    else
        print_warn "Docker not found — Prowler will be skipped. Install Docker to enable full scanning."
    fi

    # ScoutSuite
    print_subsection "Installing Python-based security tools"
    local pip_packages=("scoutsuite")
    for pkg in "${pip_packages[@]}"; do
        if pip3 show "$pkg" &>/dev/null; then
            print_success "$pkg is already installed"
        else
            print_warn "Installing $pkg..."
            pip3 install --quiet --user --upgrade "$pkg" 2>/dev/null \
                || pip3 install --quiet --user --upgrade --break-system-packages "$pkg" 2>/dev/null \
                || print_error "Failed to install $pkg (continuing anyway)"
        fi
    done

    export PATH="$HOME/.local/bin:$PATH"
    print_success "Dependency check complete"
}

###############################################################################
# USER INPUT / CREDENTIAL SETUP
###############################################################################

prompt_credentials() {
    print_section "STEP 2: CREDENTIAL & ENGAGEMENT SETUP"

    echo -e "${CYAN}Please provide the following information.${NC}"
    echo -e "${CYAN}All credentials are stored locally in your az CLI session only.${NC}"
    echo ""

    while [[ -z "$CLIENT_NAME" ]]; do
        read -rp "$(echo -e "${BOLD}Engagement/Client name${NC} (used for output folder, e.g. \"acme-corp\"): ")" CLIENT_NAME
        CLIENT_NAME=$(echo "$CLIENT_NAME" | tr -cd '[:alnum:]-_')
    done

    while [[ -z "$TENANT_ID" ]]; do
        read -rp "$(echo -e "${BOLD}Azure Tenant ID${NC}: ")" TENANT_ID
    done

    while [[ -z "$APP_ID" ]]; do
        read -rp "$(echo -e "${BOLD}App ID (Client ID / Service Principal)${NC}: ")" APP_ID
    done

    while [[ -z "$CLIENT_SECRET" ]]; do
        read -rsp "$(echo -e "${BOLD}Client Secret${NC} (input hidden): ")" CLIENT_SECRET
        echo ""
    done

    echo ""
    echo -e "${CYAN}Enter in-scope Subscription IDs (one per line, blank line when done):${NC}"
    while true; do
        read -rp "  Subscription ID (or blank to finish): " sub_id
        [[ -z "$sub_id" ]] && break
        SUBSCRIPTION_IDS+=("$sub_id")
    done

    if [[ ${#SUBSCRIPTION_IDS[@]} -eq 0 ]]; then
        print_error "At least one Subscription ID is required."
        exit 1
    fi

    if ! command -v az &>/dev/null; then
        print_error "Azure CLI is not installed or not in PATH. Cannot authenticate."
        exit 1
    fi

    print_info "Authenticating with Azure CLI as Service Principal..."
    local login_output login_status
    login_output=$(az login --service-principal \
        --username "$APP_ID" \
        --password "$CLIENT_SECRET" \
        --tenant "$TENANT_ID" \
        --output none 2>&1)
    login_status=$?

    if [[ $login_status -ne 0 ]]; then
        print_error "Azure CLI authentication failed. Azure CLI returned:"
        echo "$login_output" | sed 's/^/    /'
        print_error "Confirm the tenant ID, app/client ID, client secret value, secret expiration, and service principal status."
        exit 1
    fi

    # Validate subscription access before continuing. This catches the common case
    # where login succeeds but the service principal lacks Reader/Security Reader
    # on the provided subscription.
    local first_sub="${SUBSCRIPTION_IDS[0]}"
    local account_set_output account_set_status
    account_set_output=$(az account set --subscription "$first_sub" 2>&1)
    account_set_status=$?
    if [[ $account_set_status -ne 0 ]]; then
        print_error "Azure login succeeded, but the service principal could not access subscription: $first_sub"
        echo "$account_set_output" | sed 's/^/    /'
        print_error "Confirm the subscription ID and that the service principal has Reader + Security Reader on the in-scope subscription."
        exit 1
    fi

    # Validate credentials and get identity info
    local account_info
    account_info=$(az account show --output json 2>/dev/null)
    if [[ -z "$account_info" || "$account_info" == "{}" ]]; then
        print_error "az account show failed after login and subscription selection. Credentials or subscription access may be invalid."
        exit 1
    fi

    print_success "Authentication and subscription access validated"

    OUTPUT_DIR="$(pwd)/azure-review_${CLIENT_NAME}_${TENANT_ID:0:8}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{01-posture,02-logistics,03-visibility,04-access,05-trust,06-controls,07-tool-output,reports}

    FINDINGS_LOG="$OUTPUT_DIR/reports/findings.log"
    echo "SEVERITY|MODULE|TECHNIQUE|MESSAGE|TIME" > "$FINDINGS_LOG"

    print_success "Output directory created: $OUTPUT_DIR"
    print_info "Tenant ID:       $TENANT_ID"
    print_info "App ID:          $APP_ID"
    print_info "Subscriptions:   ${SUBSCRIPTION_IDS[*]}"
}

###############################################################################
# MODULE 1 - POSTURE REVIEW
###############################################################################

module_posture_review() {
    CURRENT_MODULE="MODULE 1: POSTURE REVIEW"
    print_section "MODULE 1: POSTURE REVIEW"
    local outdir="$OUTPUT_DIR/01-posture"

    print_subsection "Tenant & Subscription Identity"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        print_info "Setting context to subscription: $sub_id"
        az account set --subscription "$sub_id" 2>/dev/null
        az account show --output json 2>/dev/null | tee "$outdir/account-${sub_id:0:8}.json"
    done
    az account list --output json 2>/dev/null | tee "$outdir/all-subscriptions.json" | \
        jq -r '.[]? | "  → \(.id)  \(.name)  [\(.state)]"' 2>/dev/null

    print_subsection "Azure Management Group Hierarchy"
    az account management-group list --output json 2>/dev/null \
        | tee "$outdir/management-groups.json" \
        | jq -r '.[]? | "  → \(.id)  \(.displayName)"' 2>/dev/null \
        || print_info "Management group listing requires elevated permissions or not in use"

    print_subsection "Microsoft Defender for Cloud — Plans & Status"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local pricing_file="$outdir/defender-plans-${sub_id:0:8}.json"
        az security pricing list --output json 2>/dev/null | tee "$pricing_file" > /dev/null

        if [[ -s "$pricing_file" ]]; then
            print_info "Defender for Cloud plans (Subscription: $sub_id):"
            jq -r '.[]? | "  \(.name): \(.pricingTier)"' "$pricing_file" 2>/dev/null

            # Check for Free tier plans (not fully protected)
            local free_plans
            free_plans=$(jq -r '[.[]? | select(.pricingTier=="Free") | .name] | join(", ")' "$pricing_file" 2>/dev/null)
            if [[ -n "$free_plans" && "$free_plans" != "" ]]; then
                print_finding_medium "Defender for Cloud — the following plans are on FREE tier in sub $sub_id: $free_plans"
            else
                print_success "All Defender for Cloud plans are on Standard/Paid tier"
            fi
        fi
    done

    print_subsection "Azure Policy — Compliance State & Initiative Assignments"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az policy assignment list --output json 2>/dev/null \
            | tee "$outdir/policy-assignments-${sub_id:0:8}.json" > /dev/null

        local assignment_count
        assignment_count=$(jq 'length' "$outdir/policy-assignments-${sub_id:0:8}.json" 2>/dev/null || echo 0)
        print_info "Policy assignments in sub $sub_id: $assignment_count"

        # Check compliance summaries
        az policy state summarize --subscription "$sub_id" --output json 2>/dev/null \
            | tee "$outdir/policy-compliance-${sub_id:0:8}.json" > /dev/null

        local non_compliant
        non_compliant=$(jq -r '.results.nonCompliantResources // 0' \
            "$outdir/policy-compliance-${sub_id:0:8}.json" 2>/dev/null)
        if [[ "$non_compliant" -gt 0 ]]; then
            print_finding_medium "$non_compliant non-compliant resource(s) found in policy compliance scan for sub $sub_id"
        fi
    done

    print_subsection "Regulatory Compliance Frameworks in Defender for Cloud"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az security regulatory-compliance-standards list --output json 2>/dev/null \
            | tee "$outdir/regulatory-compliance-${sub_id:0:8}.json" \
            | jq -r '.[]? | "  → \(.id | split("/")[-1])  State: \(.state)"' 2>/dev/null \
            || print_info "Regulatory compliance data not available for sub $sub_id"
    done
}


###############################################################################
# MODULE 2 - LOGISTICS
###############################################################################

module_logistics() {
    CURRENT_MODULE="MODULE 2: LOGISTICS"
    print_section "MODULE 2: LOGISTICS"
    local outdir="$OUTPUT_DIR/02-logistics"

    print_subsection "Effective Permissions of Service Account"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local role_file="$outdir/sp-role-assignments-${sub_id:0:8}.json"

        az role assignment list \
            --assignee "$APP_ID" \
            --include-inherited \
            --include-groups \
            --output json 2>/dev/null | tee "$role_file" > /dev/null

        print_info "Service principal role assignments in $sub_id:"
        jq -r '.[]? | "  → \(.roleDefinitionName) | Scope: \(.scope)"' "$role_file" 2>/dev/null

        # Flag if SP has Owner or Contributor at subscription scope
        local owner_contrib
        owner_contrib=$(jq -r '[.[]? | select(
            (.roleDefinitionName=="Owner" or .roleDefinitionName=="Contributor") and
            (.scope | test("/subscriptions/[^/]+$"))
        ) | .roleDefinitionName] | join(", ")' "$role_file" 2>/dev/null)
        if [[ -n "$owner_contrib" && "$owner_contrib" != "" ]]; then
            print_finding_with_technique high "T1078.004" \
                "Service principal '$APP_ID' has '$owner_contrib' at subscription scope in $sub_id — overly privileged"
        fi
    done

    print_subsection "Enabled Azure Regions / Locations per Subscription"
    : > "$outdir/enabled-locations.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az account list-locations \
            --query "[?metadata.regionType=='Physical'].[name,displayName]" \
            --output tsv 2>/dev/null >> "$outdir/enabled-locations.txt"
    done
    sort -u "$outdir/enabled-locations.txt" > "$outdir/enabled-locations-sorted.txt"
    local loc_count
    loc_count=$(wc -l < "$outdir/enabled-locations-sorted.txt" | tr -d ' ')
    print_info "Total available physical regions: $loc_count"

    print_subsection "Resource Inventory Fingerprint"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local inv_file="$outdir/resource-inventory-${sub_id:0:8}.json"
        az resource list --output json 2>/dev/null | tee "$inv_file" > /dev/null

        local res_count
        res_count=$(jq 'length' "$inv_file" 2>/dev/null || echo 0)
        print_info "Total resources in sub $sub_id: $res_count"

        # Resource type breakdown
        jq -r '[.[]? | .type] | group_by(.) | map({type:.[0], count:length}) | sort_by(-.count)[] | "  \(.count)\t\(.type)"' \
            "$inv_file" 2>/dev/null | head -20 | tee "$outdir/resource-type-summary-${sub_id:0:8}.txt"
    done
}


###############################################################################
# MODULE 3 - VISIBILITY AUDIT
###############################################################################

module_visibility_audit() {
    CURRENT_MODULE="MODULE 3: VISIBILITY AUDIT"
    print_section "MODULE 3: VISIBILITY AUDIT"
    local outdir="$OUTPUT_DIR/03-visibility"

    ########## BLOB STORAGE PUBLIC ACCESS [T1530] ##########
    print_subsection "Azure Blob Storage — Public Access [MITRE T1530]"
    : > "$outdir/public-blob-containers.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local sa_file="$outdir/storage-accounts-${sub_id:0:8}.json"
        az storage account list --output json 2>/dev/null | tee "$sa_file" > /dev/null

        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.allowBlobPublicAccess)\t\(.id)"' \
            "$sa_file" 2>/dev/null | \
        while IFS=$'\t' read -r sa_name rg allow_public sa_id; do
            [[ -z "$sa_name" ]] && continue
            if [[ "$allow_public" == "true" ]]; then
                echo "SUB=$sub_id | SA=$sa_name | RG=$rg | allowBlobPublicAccess=true" \
                    >> "$outdir/public-blob-containers.txt"
                print_finding_with_technique critical "T1530" \
                    "Storage account '$sa_name' (RG: $rg, Sub: $sub_id) has allowBlobPublicAccess=true"
            fi
        done
    done

    ########## VMs WITH PUBLIC IPs ##########
    print_subsection "Azure VMs — Public IP Exposure"
    : > "$outdir/public-vms.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local vm_ip_file="$outdir/vm-ips-${sub_id:0:8}.json"
        az vm list-ip-addresses --output json 2>/dev/null | tee "$vm_ip_file" > /dev/null

        jq -r '.[]? | .virtualMachine as $vm |
            $vm.network.publicIpAddresses[]? |
            "\($vm.name)\t\(.ipAddress)\t\($vm.id | split("/resourceGroups/")[1] | split("/")[0])"' \
            "$vm_ip_file" 2>/dev/null | \
        while IFS=$'\t' read -r vm_name pub_ip rg; do
            [[ -z "$vm_name" ]] && continue
            echo "SUB=$sub_id | VM=$vm_name | IP=$pub_ip | RG=$rg" >> "$outdir/public-vms.txt"
            print_finding_medium "VM '$vm_name' (RG: $rg, Sub: $sub_id) has public IP: $pub_ip"
        done
    done

    ########## NSG RULES OPEN TO INTERNET [T1190] ##########
    print_subsection "Azure NSG Rules — Open to Internet (0.0.0.0/0 or *) [MITRE T1190]"
    : > "$outdir/open-nsg-rules.txt"
    local risky_ports_pattern="22|3389|3306|5432|1433|27017|6379|9200|5984|21|23|445|1521|4333|8080|8443"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local nsg_file="$outdir/nsgs-${sub_id:0:8}.json"
        az network nsg list --output json 2>/dev/null | tee "$nsg_file" > /dev/null

        jq -c '.[]?' "$nsg_file" 2>/dev/null | while read -r nsg; do
            local nsg_name rg
            nsg_name=$(echo "$nsg" | jq -r '.name')
            rg=$(echo "$nsg" | jq -r '.resourceGroup')

            # Check inbound rules open to internet
            echo "$nsg" | jq -r '
                .securityRules[]? |
                select(
                    .access=="Allow" and
                    .direction=="Inbound" and
                    (.sourceAddressPrefix=="*" or .sourceAddressPrefix=="0.0.0.0/0" or
                     .sourceAddressPrefix=="Internet" or .sourceAddressPrefix=="Any")
                ) |
                "\(.name)\t\(.destinationPortRange)\t\(.protocol)"
            ' 2>/dev/null | while IFS=$'\t' read -r rule_name port proto; do
                [[ -z "$rule_name" ]] && continue
                echo "SUB=$sub_id | NSG=$nsg_name | RG=$rg | Rule=$rule_name | Port=$port | Proto=$proto" \
                    >> "$outdir/open-nsg-rules.txt"

                if echo "$port" | grep -qE "^($risky_ports_pattern)$"; then
                    print_finding_with_technique critical "T1190" \
                        "NSG '$nsg_name' (RG: $rg, Sub: $sub_id) rule '$rule_name' exposes port $port to internet"
                else
                    print_finding_medium "NSG '$nsg_name' (Sub: $sub_id) rule '$rule_name' open to internet — Port: $port"
                fi
            done

            # Also check default rules that are overly permissive
            echo "$nsg" | jq -r '
                .defaultSecurityRules[]? |
                select(
                    .access=="Allow" and .direction=="Inbound" and
                    (.sourceAddressPrefix=="Internet" or .sourceAddressPrefix=="*")
                ) |
                "\(.name)\t\(.destinationPortRange)"
            ' 2>/dev/null | while IFS=$'\t' read -r dname dport; do
                [[ -z "$dname" ]] && continue
                print_finding_info "NSG '$nsg_name' (Sub: $sub_id) default rule '$dname' allows internet inbound — Port: $dport"
            done
        done
    done

    ########## AZURE SQL / POSTGRESQL / MYSQL PUBLIC NETWORK ACCESS ##########
    print_subsection "Azure SQL / PostgreSQL / MySQL — Public Network Access"
    : > "$outdir/public-databases.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        # Azure SQL
        az sql server list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.publicNetworkAccess)\t\(.id)"' 2>/dev/null | \
        while IFS=$'\t' read -r srv_name rg pub_net srv_id; do
            [[ -z "$srv_name" ]] && continue
            if [[ "$pub_net" != "Disabled" ]]; then
                echo "SQL | SUB=$sub_id | Server=$srv_name | RG=$rg | publicNetworkAccess=$pub_net" \
                    >> "$outdir/public-databases.txt"
                print_finding_with_technique high "T1190" \
                    "Azure SQL Server '$srv_name' (RG: $rg, Sub: $sub_id) has publicNetworkAccess=$pub_net"
            fi
            # Save for controls module
            az sql server firewall-rule list --server "$srv_name" --resource-group "$rg" \
                --output json 2>/dev/null > "$outdir/sql-fw-rules-${srv_name}.json"
        done

        # PostgreSQL
        az postgres server list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.publicNetworkAccess)"' 2>/dev/null | \
        while IFS=$'\t' read -r srv_name rg pub_net; do
            [[ -z "$srv_name" ]] && continue
            if [[ "$pub_net" != "Disabled" ]]; then
                echo "PostgreSQL | SUB=$sub_id | Server=$srv_name | RG=$rg | publicNetworkAccess=$pub_net" \
                    >> "$outdir/public-databases.txt"
                print_finding_with_technique high "T1190" \
                    "PostgreSQL Server '$srv_name' (RG: $rg, Sub: $sub_id) has publicNetworkAccess=$pub_net"
            fi
        done

        # MySQL
        az mysql server list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.publicNetworkAccess)"' 2>/dev/null | \
        while IFS=$'\t' read -r srv_name rg pub_net; do
            [[ -z "$srv_name" ]] && continue
            if [[ "$pub_net" != "Disabled" ]]; then
                echo "MySQL | SUB=$sub_id | Server=$srv_name | RG=$rg | publicNetworkAccess=$pub_net" \
                    >> "$outdir/public-databases.txt"
                print_finding_with_technique high "T1190" \
                    "MySQL Server '$srv_name' (RG: $rg, Sub: $sub_id) has publicNetworkAccess=$pub_net"
            fi
        done
    done

    ########## MANAGED DISK SNAPSHOTS — PUBLIC ACCESS ##########
    print_subsection "Managed Disk Snapshots — Public Network Access"
    : > "$outdir/public-snapshots.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az snapshot list --output json 2>/dev/null | \
        jq -r '.[]? | select(.networkAccessPolicy=="AllowAll" or .publicNetworkAccess=="Enabled") |
            "\(.name)\t\(.resourceGroup)\t\(.networkAccessPolicy)\t\(.diskSizeGb)"' 2>/dev/null | \
        while IFS=$'\t' read -r snap_name rg policy size_gb; do
            [[ -z "$snap_name" ]] && continue
            echo "SUB=$sub_id | Snapshot=$snap_name | RG=$rg | Policy=$policy | Size=${size_gb}GB" \
                >> "$outdir/public-snapshots.txt"
            print_finding_with_technique critical "T1530" \
                "Disk snapshot '$snap_name' (RG: $rg, Sub: $sub_id) has public network access ($policy)"
        done
    done

    ########## AZURE FUNCTIONS — ANONYMOUS AUTH [T1190] ##########
    print_subsection "Azure Functions — Anonymous Authentication Level [MITRE T1190]"
    : > "$outdir/anonymous-functions.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local fa_file="$outdir/function-apps-${sub_id:0:8}.json"
        az functionapp list --output json 2>/dev/null | tee "$fa_file" > /dev/null

        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.id)"' "$fa_file" 2>/dev/null | \
        while IFS=$'\t' read -r fa_name rg fa_id; do
            [[ -z "$fa_name" ]] && continue

            # Get functions within the app
            local funcs
            funcs=$(az functionapp function list \
                --name "$fa_name" --resource-group "$rg" \
                --output json 2>/dev/null)
            if [[ -n "$funcs" && "$funcs" != "[]" ]]; then
                echo "$funcs" | jq -r '.[]? | select(.config.bindings[]?.authLevel=="anonymous") | .name' \
                    2>/dev/null | while read -r func_name; do
                    [[ -z "$func_name" ]] && continue
                    echo "SUB=$sub_id | FunctionApp=$fa_name | Function=$func_name | Auth=anonymous" \
                        >> "$outdir/anonymous-functions.txt"
                    print_finding_with_technique high "T1190" \
                        "Function App '$fa_name' / function '$func_name' (Sub: $sub_id) allows anonymous invocation"
                done
            fi
        done
    done

    ########## AZURE SHARED IMAGE GALLERY — PUBLIC IMAGES ##########
    print_subsection "Azure Shared Image Gallery — Public Images"
    : > "$outdir/public-images.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az sig list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)"' 2>/dev/null | \
        while IFS=$'\t' read -r gallery rg; do
            [[ -z "$gallery" ]] && continue
            az sig image-definition list \
                --gallery-name "$gallery" --resource-group "$rg" \
                --output json 2>/dev/null | \
            jq -r --arg g "$gallery" '.[]? | select(.publishingProfile.replicaCount>0) |
                "\($g)\t\(.name)\t\(.publishingProfile.targetRegions // [] | map(.name) | join(","))"' \
                2>/dev/null | \
            while IFS=$'\t' read -r gal def regions; do
                echo "SUB=$sub_id | Gallery=$gal | ImageDef=$def | Regions=$regions" \
                    >> "$outdir/public-images.txt"
                print_finding_info "Shared Image Gallery '$gal' image '$def' (Sub: $sub_id) — review audience scope"
            done
        done
    done

    ########## AZURE LOAD BALANCER & APPLICATION GATEWAY — PUBLIC ##########
    print_subsection "Azure Load Balancers & Application Gateways — Internet-Facing"
    : > "$outdir/public-load-balancers.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        # Load Balancers
        az network lb list --output json 2>/dev/null | \
        jq -r '.[]? | select(.frontendIPConfigurations[]?.publicIPAddress!=null) |
            "\(.name)\t\(.resourceGroup)\t\(.sku.name)"' 2>/dev/null | \
        while IFS=$'\t' read -r lb_name rg sku; do
            echo "SUB=$sub_id | LB=$lb_name | RG=$rg | SKU=$sku" >> "$outdir/public-load-balancers.txt"
            print_finding_info "Internet-facing Load Balancer '$lb_name' (RG: $rg, Sub: $sub_id, SKU: $sku)"
        done

        # Application Gateways
        az network application-gateway list --output json 2>/dev/null | \
        jq -r '.[]? | select(.frontendIPConfigurations[]?.publicIPAddress!=null) |
            "\(.name)\t\(.resourceGroup)\t\(.sku.name)"' 2>/dev/null | \
        while IFS=$'\t' read -r agw_name rg sku; do
            echo "SUB=$sub_id | AppGW=$agw_name | RG=$rg | SKU=$sku" >> "$outdir/public-load-balancers.txt"
            print_finding_info "Internet-facing Application Gateway '$agw_name' (RG: $rg, Sub: $sub_id)"
        done
    done

    ########## AZURE API MANAGEMENT — PUBLIC ENDPOINTS ##########
    print_subsection "Azure API Management — Public Endpoints"
    : > "$outdir/public-apim.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az apim list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.publicNetworkAccess)\t\(.gatewayUrl)"' 2>/dev/null | \
        while IFS=$'\t' read -r apim_name rg pub_net gw_url; do
            [[ -z "$apim_name" ]] && continue
            echo "SUB=$sub_id | APIM=$apim_name | RG=$rg | publicNetworkAccess=$pub_net | URL=$gw_url" \
                >> "$outdir/public-apim.txt"
            if [[ "$pub_net" == "Enabled" ]]; then
                print_finding_medium "API Management '$apim_name' (RG: $rg, Sub: $sub_id) has public network access enabled"
            fi
        done
    done

    ########## AZURE IMDS — POLICY ENFORCEMENT [T1552.005] ##########
    print_subsection "Azure IMDS Enforcement via Policy [MITRE T1552.005]"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local imds_policy_found=false

        # Check if there's a policy restricting IMDS or enforcing metadata endpoint controls
        local policies
        policies=$(az policy assignment list --output json 2>/dev/null)
        if echo "$policies" | grep -qi "metadata\|imds\|instance-metadata"; then
            imds_policy_found=true
            print_success "Policy assignment referencing IMDS/metadata found in sub $sub_id"
        fi

        if [[ "$imds_policy_found" == "false" ]]; then
            print_finding_with_technique medium "T1552.005" \
                "No Azure Policy found enforcing IMDS endpoint restriction in sub $sub_id — consider deploying CIS policy initiative"
        fi

        # Check VMs for any IMDS-related extensions
        az vm list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)"' 2>/dev/null | \
        while IFS=$'\t' read -r vm_name rg; do
            [[ -z "$vm_name" ]] && continue
            local ext_list
            ext_list=$(az vm extension list --vm-name "$vm_name" --resource-group "$rg" \
                --output json 2>/dev/null)
            # Note: Azure does not have IMDSv1/v2 equivalent enforcement at VM level
            # This is a policy-level control
        done
    done

    ########## FUNCTION APPS — DEPRECATED RUNTIMES & SECRET APP SETTINGS [T1552, T1195.002] ##########
    print_subsection "Function Apps — Deprecated Runtimes & Secret App Settings [MITRE T1552, T1195.002]"
    local fa_findings_file="$outdir/function-app-findings.txt"
    : > "$fa_findings_file"

    # Deprecated runtime versions
    local -a DEPRECATED_PYTHON=("3.6" "3.7" "2.7")
    local -a DEPRECATED_NODE=("4" "6" "8" "10" "12")
    local -a DEPRECATED_DOTNET=("2.1" "3.1")
    local -a DEPRECATED_JAVA=("8" "11")

    local -a SECRET_APP_SETTING_PATTERNS=(
        "PASSWORD" "PASSWD" "SECRET" "API_KEY" "APIKEY"
        "TOKEN" "AUTH" "CREDENTIAL" "PRIVATE_KEY" "ACCESS_KEY"
        "CLIENT_SECRET" "DB_PASS" "DATABASE_PASSWORD" "CONN_STR" "CONNECTIONSTRING"
    )

    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        jq -r '.[]? | "\(.name)\t\(.resourceGroup)"' "$outdir/function-apps-${sub_id:0:8}.json" 2>/dev/null | \
        while IFS=$'\t' read -r fa_name rg; do
            [[ -z "$fa_name" ]] && continue

            # Get site config for runtime version
            local site_config
            site_config=$(az functionapp config show \
                --name "$fa_name" --resource-group "$rg" \
                --output json 2>/dev/null)

            local python_ver node_ver dotnet_ver java_ver
            python_ver=$(echo "$site_config" | jq -r '.pythonVersion // ""' 2>/dev/null)
            node_ver=$(echo "$site_config" | jq -r '.nodeVersion // ""' 2>/dev/null | grep -oE '[0-9]+' | head -1)
            dotnet_ver=$(echo "$site_config" | jq -r '.netFrameworkVersion // ""' 2>/dev/null | sed 's/v//')
            java_ver=$(echo "$site_config" | jq -r '.javaVersion // ""' 2>/dev/null)

            for dep in "${DEPRECATED_PYTHON[@]}"; do
                if [[ "$python_ver" == *"$dep"* ]]; then
                    print_finding_with_technique medium "T1195.002" \
                        "Function App '$fa_name' (Sub: $sub_id) uses deprecated Python runtime: $python_ver"
                    echo "DEPRECATED_RUNTIME | $sub_id | $fa_name | python=$python_ver" >> "$fa_findings_file"
                fi
            done

            for dep in "${DEPRECATED_NODE[@]}"; do
                if [[ "$node_ver" == "$dep" ]]; then
                    print_finding_with_technique medium "T1195.002" \
                        "Function App '$fa_name' (Sub: $sub_id) uses deprecated Node runtime: $node_ver"
                    echo "DEPRECATED_RUNTIME | $sub_id | $fa_name | node=$node_ver" >> "$fa_findings_file"
                fi
            done

            # Check app settings for secret patterns
            local app_settings
            app_settings=$(az functionapp config appsettings list \
                --name "$fa_name" --resource-group "$rg" \
                --output json 2>/dev/null)

            if [[ -n "$app_settings" && "$app_settings" != "[]" ]]; then
                echo "$app_settings" | jq -r '.[]? | .name' 2>/dev/null | \
                while read -r setting_name; do
                    [[ -z "$setting_name" ]] && continue
                    local upper_name
                    upper_name=$(echo "$setting_name" | tr '[:lower:]' '[:upper:]')
                    for pattern in "${SECRET_APP_SETTING_PATTERNS[@]}"; do
                        if [[ "$upper_name" == *"$pattern"* ]]; then
                            print_finding_high \
                                "[T1552] Function App '$fa_name' (Sub: $sub_id) has suspicious app setting '$setting_name'"
                            echo "SECRET_APP_SETTING | $sub_id | $fa_name | Setting=$setting_name" >> "$fa_findings_file"
                            break
                        fi
                    done
                done
            fi
        done
    done

    if [[ ! -s "$fa_findings_file" ]]; then
        print_success "No Function App runtime or app setting issues detected"
    fi
}


###############################################################################
# MODULE 4 - ACCESS VERIFICATION (Entra ID Deep-Dive)
###############################################################################

module_access_verification() {
    CURRENT_MODULE="MODULE 4: ACCESS"
    print_section "MODULE 4: ACCESS VERIFICATION (Entra ID Deep-Dive)"
    local outdir="$OUTPUT_DIR/04-access"

    print_subsection "Entra ID — Users Without MFA Registered [MITRE T1078.004]"
    # Get all users with sign-in activity
    local users_file="$outdir/all-users.json"
    graph_get "https://graph.microsoft.com/v1.0/users?\$select=id,displayName,userPrincipalName,accountEnabled,userType,signInActivity&\$top=999" \
        | tee "$users_file" > /dev/null

    local total_users
    total_users=$(jq '.value | length' "$users_file" 2>/dev/null || echo 0)
    print_info "Total users retrieved: $total_users"

    # Get authentication methods (MFA) for users — requires batch approach
    # Check auth methods registration campaign summary
    local mfa_report
    mfa_report=$(graph_get "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?\$top=999")
    echo "$mfa_report" > "$outdir/mfa-registration.json"

    # Count users without MFA
    local no_mfa_users
    no_mfa_users=$(jq -r '.value[]? | select(
        .isMfaRegistered==false and .isEnabled==true and .isSsprRegistered==false
    ) | .userPrincipalName' "$outdir/mfa-registration.json" 2>/dev/null | tee "$outdir/users-no-mfa.txt")

    local no_mfa_count
    no_mfa_count=$(wc -l < "$outdir/users-no-mfa.txt" 2>/dev/null | tr -d ' ')
    if [[ "$no_mfa_count" -gt 0 ]]; then
        print_finding_with_technique high "T1078.004" \
            "$no_mfa_count enabled user(s) have NO MFA method registered — see users-no-mfa.txt"
        head -10 "$outdir/users-no-mfa.txt" | while read -r upn; do
            [[ -n "$upn" ]] && echo -e "        ${RED}→ $upn${NC}"
        done
        [[ "$no_mfa_count" -gt 10 ]] && echo -e "        ${YELLOW}... and $((no_mfa_count-10)) more${NC}"
    else
        print_success "All users appear to have MFA registered (or report API returned no data)"
    fi

    print_subsection "Guest Accounts (External Users) [MITRE T1078.004]"
    local guest_file="$outdir/guest-users.json"
    graph_get "https://graph.microsoft.com/v1.0/users?\$filter=userType eq 'Guest'&\$top=999" \
        | tee "$guest_file" > /dev/null

    local guest_count
    guest_count=$(jq '.value | length' "$guest_file" 2>/dev/null || echo 0)
    print_finding_info "Guest (external) accounts in tenant: $guest_count"
    if [[ "$guest_count" -gt 50 ]]; then
        print_finding_medium "Large number of guest accounts ($guest_count) — review for stale/unnecessary external access"
    fi
    jq -r '.value[]? | "  → \(.userPrincipalName) | Enabled: \(.accountEnabled)"' \
        "$guest_file" 2>/dev/null | head -20 > "$outdir/guest-accounts.txt"

    print_subsection "Privileged Identity Management (PIM) — Permanent vs Eligible Assignments"
    # Check permanent privileged role assignments
    local perm_roles_file="$outdir/permanent-role-assignments.json"
    graph_get "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition" \
        | tee "$perm_roles_file" > /dev/null

    local perm_count
    perm_count=$(jq '.value | length' "$perm_roles_file" 2>/dev/null || echo 0)
    print_info "Permanent Entra ID role assignments: $perm_count"

    # Check eligible assignments (PIM)
    local eligible_file="$outdir/pim-eligible-assignments.json"
    graph_get "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?\$expand=principal,roleDefinition" \
        | tee "$eligible_file" > /dev/null

    local eligible_count
    eligible_count=$(jq '.value | length' "$eligible_file" 2>/dev/null || echo 0)
    print_info "PIM-eligible (time-bound) role assignments: $eligible_count"

    if [[ "$perm_count" -gt 0 && "$eligible_count" -eq 0 ]]; then
        print_finding_with_technique medium "T1078.004" \
            "All privileged assignments appear PERMANENT ($perm_count) with no PIM eligible assignments found — PIM may not be in use"
    fi

    print_subsection "Global Administrators Count [MITRE T1078.004]"
    local ga_file="$outdir/global-admins.json"
    # Global Administrator role ID is '62e90394-69f5-4237-9190-012177145e10'
    graph_get "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&\$expand=principal" \
        | tee "$ga_file" > /dev/null

    local ga_count
    ga_count=$(jq '.value | length' "$ga_file" 2>/dev/null || echo 0)
    print_info "Global Administrator assignments: $ga_count"
    jq -r '.value[]? | "  → \(.principal.displayName // .principal.userPrincipalName) [\(.principal."@odata.type")]"' \
        "$ga_file" 2>/dev/null

    if [[ "$ga_count" -gt 5 ]]; then
        print_finding_with_technique high "T1078.004" \
            "Excessive Global Administrators found: $ga_count (CIS recommends ≤5)"
    elif [[ "$ga_count" -gt 0 ]]; then
        print_finding_info "$ga_count Global Administrator(s) assigned — review necessity of each"
    fi

    print_subsection "Service Principals with Owner/Contributor at Subscription [MITRE T1078.004]"
    : > "$outdir/overprivileged-sps.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az role assignment list \
            --include-inherited \
            --query "[?principalType=='ServicePrincipal' && (roleDefinitionName=='Owner' || roleDefinitionName=='Contributor')]" \
            --output json 2>/dev/null | \
        jq -r '.[]? | "\(.principalId)\t\(.principalName)\t\(.roleDefinitionName)\t\(.scope)"' 2>/dev/null | \
        while IFS=$'\t' read -r sp_id sp_name role scope; do
            [[ -z "$sp_id" ]] && continue
            if echo "$scope" | grep -qE "^/subscriptions/[^/]+$"; then
                echo "SUB=$sub_id | SP=$sp_name ($sp_id) | Role=$role | Scope=$scope" \
                    >> "$outdir/overprivileged-sps.txt"
                print_finding_with_technique high "T1078.004" \
                    "Service principal '$sp_name' has '$role' at subscription scope in $sub_id"
            fi
        done
    done

    print_subsection "Stale App Registrations & Service Principals"
    local apps_file="$outdir/app-registrations.json"
    graph_get "https://graph.microsoft.com/v1.0/applications?\$select=id,displayName,createdDateTime,passwordCredentials,keyCredentials&\$top=999" \
        | tee "$apps_file" > /dev/null

    # Find apps with expired credentials
    local now_epoch
    now_epoch=$(date +%s)
    jq -r '.value[]? | . as $app |
        (.passwordCredentials[]?, .keyCredentials[]?) |
        "\($app.displayName)\t\(.endDateTime)\t\($app.id)"' "$apps_file" 2>/dev/null | \
    while IFS=$'\t' read -r app_name end_dt app_id; do
        [[ -z "$app_name" ]] && continue
        if [[ -n "$end_dt" ]]; then
            local end_epoch
            end_epoch=$(date -d "$end_dt" +%s 2>/dev/null || \
                        date -j -f "%Y-%m-%dT%H:%M:%SZ" "$end_dt" +%s 2>/dev/null || echo 0)
            if [[ "$end_epoch" -lt "$now_epoch" && "$end_epoch" -gt 0 ]]; then
                echo "EXPIRED_CREDENTIAL | $app_name | $app_id | Expired=$end_dt" \
                    >> "$outdir/stale-app-registrations.txt"
                print_finding_medium "App registration '$app_name' has an EXPIRED credential (expired: $end_dt)"
            fi
        fi
    done

    # Get service principals with credential expiry
    local sp_file="$outdir/service-principals.json"
    graph_get "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=id,displayName,appId,passwordCredentials,keyCredentials,servicePrincipalType&\$top=999" \
        | tee "$sp_file" > /dev/null

    print_subsection "Conditional Access Policies Coverage"
    local ca_file="$outdir/conditional-access-policies.json"
    graph_get "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
        | tee "$ca_file" > /dev/null

    local ca_count enabled_ca disabled_ca
    ca_count=$(jq '.value | length' "$ca_file" 2>/dev/null || echo 0)
    enabled_ca=$(jq '[.value[]? | select(.state=="enabled")] | length' "$ca_file" 2>/dev/null || echo 0)
    disabled_ca=$(jq '[.value[]? | select(.state=="disabled")] | length' "$ca_file" 2>/dev/null || echo 0)

    print_info "Conditional Access policies — Total: $ca_count | Enabled: $enabled_ca | Disabled: $disabled_ca"
    jq -r '.value[]? | "  → [\(.state | ascii_upcase)] \(.displayName)"' "$ca_file" 2>/dev/null

    if [[ "$ca_count" -eq 0 ]]; then
        print_finding_with_technique critical "T1078.004" \
            "No Conditional Access policies found — tenant has no CA controls enforced"
    elif [[ "$enabled_ca" -eq 0 ]]; then
        print_finding_with_technique critical "T1078.004" \
            "All $ca_count Conditional Access policies are DISABLED — no CA controls enforced"
    else
        # Check if there's MFA policy
        local mfa_policy
        mfa_policy=$(jq -r '.value[]? | select(.state=="enabled") |
            select(.grantControls.builtInControls[]?=="mfa") | .displayName' \
            "$ca_file" 2>/dev/null | head -3)
        if [[ -z "$mfa_policy" ]]; then
            print_finding_with_technique high "T1078.004" \
                "No enabled Conditional Access policy found enforcing MFA (grantControl=mfa)"
        else
            print_success "CA policy with MFA grant control found: $mfa_policy"
        fi
    fi

    if [[ "$disabled_ca" -gt 0 ]]; then
        print_finding_medium "$disabled_ca Conditional Access policy/policies are DISABLED — review if intentional"
    fi

    print_subsection "Azure AD Password Protection Policy"
    local authpolicy
    authpolicy=$(graph_get "https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    echo "$authpolicy" > "$outdir/authorization-policy.json"

    local pwpolicy
    pwpolicy=$(graph_get "https://graph.microsoft.com/beta/policies/passwordAuthenticationMethod")
    echo "$pwpolicy" > "$outdir/password-auth-policy.json"

    # Check tenant allow self-service password reset
    local sspr_enabled
    sspr_enabled=$(echo "$authpolicy" | jq -r '.allowInvitesFrom // "adminsAndGuestInviters"' 2>/dev/null)
    print_info "Password protection policy saved to password-auth-policy.json — review for lockout thresholds"

    print_subsection "Entra ID Sign-In Activity (Stale Accounts)"
    # Already fetched in users_file — identify accounts with no recent sign-in
    local stale_file="$outdir/stale-accounts.txt"
    : > "$stale_file"
    local cutoff_date
    cutoff_date=$(date -d '90 days ago' +%Y-%m-%dT%H:%M:%S 2>/dev/null || \
                  date -v-90d +%Y-%m-%dT%H:%M:%S 2>/dev/null)

    jq -r --arg cutoff "$cutoff_date" '.value[]? |
        select(.accountEnabled==true and .userType!="Guest") |
        select(
            (.signInActivity.lastSignInDateTime == null) or
            (.signInActivity.lastSignInDateTime < $cutoff)
        ) |
        "\(.userPrincipalName)\t\(.signInActivity.lastSignInDateTime // "never")"' \
        "$users_file" 2>/dev/null | \
    while IFS=$'\t' read -r upn last_sign; do
        echo "$upn | LastSignIn=$last_sign" >> "$stale_file"
    done

    local stale_count
    stale_count=$(wc -l < "$stale_file" 2>/dev/null | tr -d ' ')
    if [[ "$stale_count" -gt 0 ]]; then
        print_finding_with_technique medium "T1078.004" \
            "$stale_count enabled user account(s) have not signed in for >90 days or have never signed in — stale-accounts.txt"
    else
        print_success "No stale enabled accounts detected (or sign-in activity data not available)"
    fi
}


###############################################################################
# MODULE 5 - TRUST VERIFICATION
###############################################################################

module_trust_verification() {
    CURRENT_MODULE="MODULE 5: TRUST"
    print_section "MODULE 5: TRUST VERIFICATION"
    local outdir="$OUTPUT_DIR/05-trust"

    print_subsection "Cross-Tenant Access Settings [MITRE T1199]"
    local cta_file="$outdir/cross-tenant-access.json"
    graph_get "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners" \
        | tee "$cta_file" > /dev/null

    local cta_count
    cta_count=$(jq '.value | length' "$cta_file" 2>/dev/null || echo 0)
    print_info "Cross-tenant access partner policies configured: $cta_count"
    if [[ "$cta_count" -gt 0 ]]; then
        jq -r '.value[]? | "  → TenantID: \(.tenantId) | Inbound: \(.inboundTrust.isMfaAccepted) | B2B: \(.b2bCollaborationInbound.usersAndGroups.accessType)"' \
            "$cta_file" 2>/dev/null
        print_finding_info "Cross-tenant access policies exist — review for unintended trust relationships"
    fi

    # Check default cross-tenant settings
    local cta_default
    cta_default=$(graph_get "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default")
    echo "$cta_default" > "$outdir/cross-tenant-default.json"

    print_subsection "External Identities & B2B Collaboration Settings"
    local extid_file="$outdir/external-id-settings.json"
    graph_get "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
        | tee "$extid_file" > /dev/null

    local allow_invites
    allow_invites=$(jq -r '.allowInvitesFrom // "adminsAndGuestInviters"' "$extid_file" 2>/dev/null)
    print_info "B2B guest invite policy (allowInvitesFrom): $allow_invites"
    if [[ "$allow_invites" == "everyone" ]]; then
        print_finding_with_technique high "T1199" \
            "B2B guest invitations allowed from 'everyone' — any internal user can invite external guests"
    fi

    print_subsection "Azure Lighthouse Delegations (Cross-Tenant Management) [MITRE T1199]"
    : > "$outdir/lighthouse-delegations.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local lighthouse
        lighthouse=$(az managedservices assignment list --output json 2>/dev/null)
        if [[ -n "$lighthouse" && "$lighthouse" != "[]" ]]; then
            echo "$lighthouse" > "$outdir/lighthouse-assignments-${sub_id:0:8}.json"
            local lh_count
            lh_count=$(echo "$lighthouse" | jq 'length' 2>/dev/null || echo 0)
            echo "SUB=$sub_id | Lighthouse assignments: $lh_count" >> "$outdir/lighthouse-delegations.txt"
            print_finding_with_technique high "T1199" \
                "$lh_count Azure Lighthouse delegation(s) found in sub $sub_id — cross-tenant management access exists"
            echo "$lighthouse" | jq -r '.[]? | "  → \(.id | split("/")[-1])"' 2>/dev/null
        fi
    done

    print_subsection "VNet Peering Connections [MITRE T1199]"
    : > "$outdir/vnet-peerings.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az network vnet list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)"' 2>/dev/null | \
        while IFS=$'\t' read -r vnet_name rg; do
            [[ -z "$vnet_name" ]] && continue
            local peerings
            peerings=$(az network vnet peering list \
                --vnet-name "$vnet_name" --resource-group "$rg" \
                --output json 2>/dev/null)
            if [[ -n "$peerings" && "$peerings" != "[]" ]]; then
                echo "$peerings" | jq -r --arg vnet "$vnet_name" --arg sub "$sub_id" \
                    '.[]? | "SUB=\($sub) | VNet=\($vnet) | PeeringTo=\(.remoteVirtualNetwork.id | split("/")[-1]) | State=\(.peeringState)"' \
                    2>/dev/null >> "$outdir/vnet-peerings.txt"

                # Flag cross-subscription peerings
                echo "$peerings" | jq -r --arg sub "$sub_id" \
                    '.[]? | select(.remoteVirtualNetwork.id | test("/subscriptions/") and (test("/subscriptions/\($sub)/") | not)) |
                    "\(.name)\t\(.remoteVirtualNetwork.id)"' 2>/dev/null | \
                while IFS=$'\t' read -r peer_name remote_id; do
                    print_finding_with_technique medium "T1199" \
                        "VNet '$vnet_name' (Sub: $sub_id) has cross-subscription peering '$peer_name' → $remote_id"
                done
            fi
        done
    done

    print_subsection "Private Endpoints vs Public Endpoints"
    : > "$outdir/private-endpoints.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az network private-endpoint list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.privateLinkServiceConnections[0].privateLinkServiceId // "N/A")"' \
            2>/dev/null | \
        while IFS=$'\t' read -r pe_name rg target_id; do
            echo "SUB=$sub_id | PE=$pe_name | RG=$rg | Target=$target_id" >> "$outdir/private-endpoints.txt"
        done
        local pe_count
        pe_count=$(wc -l < "$outdir/private-endpoints.txt" 2>/dev/null | tr -d ' ')
        print_info "Private endpoints in sub $sub_id: $pe_count"
    done

    print_subsection "Managed Identity Assignments"
    : > "$outdir/managed-identities.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        # User-assigned managed identities
        az identity list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.clientId)\t\(.principalId)"' 2>/dev/null | \
        while IFS=$'\t' read -r mi_name rg client_id principal_id; do
            echo "SUB=$sub_id | ManagedIdentity=$mi_name | RG=$rg | ClientID=$client_id" \
                >> "$outdir/managed-identities.txt"
        done

        # VMs with system-assigned managed identity
        az vm list --query "[?identity.type!=null].[name,resourceGroup,identity.type,identity.principalId]" \
            --output tsv 2>/dev/null | \
        while IFS=$'\t' read -r vm_name rg identity_type principal_id; do
            [[ -z "$vm_name" ]] && continue
            echo "SUB=$sub_id | VM=$vm_name | RG=$rg | IdentityType=$identity_type" \
                >> "$outdir/managed-identities.txt"
            # Check if the managed identity has elevated roles
            if [[ -n "$principal_id" ]]; then
                local vm_roles
                vm_roles=$(az role assignment list \
                    --assignee "$principal_id" \
                    --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" \
                    --output json 2>/dev/null)
                if [[ -n "$vm_roles" && "$vm_roles" != "[]" ]]; then
                    print_finding_with_technique high "T1078.004" \
                        "VM '$vm_name' (Sub: $sub_id) managed identity has Owner/Contributor role assigned"
                fi
            fi
        done
    done

    print_subsection "Federated Identity Credentials on App Registrations [MITRE T1199]"
    local fic_file="$outdir/federated-identity-credentials.txt"
    : > "$fic_file"
    jq -r '.value[]? | "\(.id)\t\(.displayName)"' \
        "$OUTPUT_DIR/04-access/app-registrations.json" 2>/dev/null | \
    while IFS=$'\t' read -r app_id app_name; do
        [[ -z "$app_id" ]] && continue
        local fics
        fics=$(graph_get "https://graph.microsoft.com/v1.0/applications/${app_id}/federatedIdentityCredentials")
        local fic_count
        fic_count=$(echo "$fics" | jq '.value | length' 2>/dev/null || echo 0)
        if [[ "$fic_count" -gt 0 ]]; then
            echo "App: $app_name | FederatedCreds: $fic_count" >> "$fic_file"
            echo "$fics" | jq -r '.value[]? | "  → \(.name) | Issuer: \(.issuer) | Subject: \(.subject)"' \
                2>/dev/null >> "$fic_file"
            print_finding_info "App '$app_name' has $fic_count federated identity credential(s) — review issuer trust"
        fi
    done
}


###############################################################################
# MODULE 6 - CONTROLS VERIFICATION
###############################################################################

module_controls_verification() {
    CURRENT_MODULE="MODULE 6: CONTROLS"
    print_section "MODULE 6: CONTROLS VERIFICATION"
    local outdir="$OUTPUT_DIR/06-controls"

    ########## AZURE MONITOR DIAGNOSTIC SETTINGS [T1562.008] ##########
    print_subsection "Azure Monitor — Diagnostic Settings on Critical Resources [MITRE T1562.008]"
    local diag_gaps_file="$outdir/diagnostic-settings-gaps.txt"
    : > "$diag_gaps_file"

    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        # Check each resource type for diagnostic settings
        local resource_types=(
            "Microsoft.KeyVault/vaults"
            "Microsoft.Storage/storageAccounts"
            "Microsoft.Network/networkSecurityGroups"
            "Microsoft.Network/loadBalancers"
            "Microsoft.Web/sites"
            "Microsoft.Sql/servers/databases"
            "Microsoft.ContainerService/managedClusters"
            "Microsoft.Network/applicationGateways"
            "Microsoft.ApiManagement/service"
        )

        for rtype in "${resource_types[@]}"; do
            az resource list --resource-type "$rtype" --output json 2>/dev/null | \
            jq -r '.[]? | "\(.id)\t\(.name)\t\(.resourceGroup)"' 2>/dev/null | \
            while IFS=$'\t' read -r res_id res_name rg; do
                [[ -z "$res_id" ]] && continue
                local diag_settings
                diag_settings=$(az monitor diagnostic-settings list \
                    --resource "$res_id" --output json 2>/dev/null)
                local ds_count
                ds_count=$(echo "$diag_settings" | jq 'length' 2>/dev/null || echo 0)
                if [[ "$ds_count" -eq 0 ]]; then
                    echo "SUB=$sub_id | Type=$rtype | Resource=$res_name | RG=$rg | NO DIAGNOSTIC SETTINGS" \
                        >> "$diag_gaps_file"
                    print_finding_with_technique high "T1562.008" \
                        "Resource '$res_name' ($rtype, RG: $rg, Sub: $sub_id) has NO diagnostic settings configured"
                fi
            done
        done
    done

    local diag_gap_count
    diag_gap_count=$(wc -l < "$diag_gaps_file" 2>/dev/null | tr -d ' ')
    [[ "$diag_gap_count" -eq 0 ]] && print_success "All sampled resources have diagnostic settings configured"

    ########## AZURE ACTIVITY LOG RETENTION [T1562.008] ##########
    print_subsection "Azure Activity Log Retention & Export [MITRE T1562.008]"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local log_profiles
        log_profiles=$(az monitor log-profiles list --output json 2>/dev/null)
        echo "$log_profiles" > "$outdir/activity-log-profiles-${sub_id:0:8}.json"

        local profile_count
        profile_count=$(echo "$log_profiles" | jq 'length' 2>/dev/null || echo 0)
        if [[ "$profile_count" -eq 0 ]]; then
            print_finding_with_technique high "T1562.008" \
                "No Activity Log export profiles found in sub $sub_id — activity logs may not be retained/exported"
        else
            # Check retention period
            echo "$log_profiles" | jq -r '.[]? | "\(.name)\t\(.retentionPolicy.days)\t\(.retentionPolicy.enabled)\t\(.storageAccountId)"' \
                2>/dev/null | \
            while IFS=$'\t' read -r lp_name days enabled sa_id; do
                print_info "Log profile '$lp_name': Retention=${days}d | Enabled=$enabled"
                if [[ "$enabled" == "true" && "$days" -lt 365 ]]; then
                    print_finding_medium "Activity Log profile '$lp_name' (Sub: $sub_id) retention is ${days} days (CIS recommends ≥365)"
                fi
                if [[ "$enabled" != "true" ]]; then
                    print_finding_with_technique high "T1562.008" \
                        "Activity Log profile '$lp_name' (Sub: $sub_id) retention policy is DISABLED"
                fi
            done
        fi
    done

    ########## MICROSOFT DEFENDER FOR CLOUD PLANS ##########
    print_subsection "Microsoft Defender for Cloud — Per-Plan Coverage"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local pricing_file="$OUTPUT_DIR/01-posture/defender-plans-${sub_id:0:8}.json"
        if [[ -f "$pricing_file" ]]; then
            local critical_plans=("VirtualMachines" "SqlServers" "AppServices" "StorageAccounts" "KeyVaults" "Arm" "Dns" "ContainerRegistry" "KubernetesService")
            for plan in "${critical_plans[@]}"; do
                local tier
                tier=$(jq -r --arg p "$plan" '.[]? | select(.name==$p) | .pricingTier' "$pricing_file" 2>/dev/null)
                if [[ "$tier" == "Free" ]]; then
                    print_finding_medium "Defender for Cloud plan '$plan' is on FREE tier in sub $sub_id — enhanced protection disabled"
                fi
            done
        fi
    done

    ########## MICROSOFT SENTINEL ##########
    print_subsection "Microsoft Sentinel — Workspace Connection"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local sentinel_ws
        sentinel_ws=$(az security workspace-setting list --output json 2>/dev/null)
        echo "$sentinel_ws" > "$outdir/security-workspace-${sub_id:0:8}.json"

        # Check for Sentinel (Log Analytics workspaces with Sentinel enabled)
        local law_list
        law_list=$(az monitor log-analytics workspace list --output json 2>/dev/null)
        local law_count
        law_count=$(echo "$law_list" | jq 'length' 2>/dev/null || echo 0)
        if [[ "$law_count" -eq 0 ]]; then
            print_finding_medium "No Log Analytics Workspace found in sub $sub_id — Microsoft Sentinel may not be deployed"
        else
            print_info "Log Analytics Workspaces in sub $sub_id: $law_count — verify Sentinel is enabled"
            echo "$law_list" | jq -r '.[]? | "  → \(.name) | RG: \(.resourceGroup) | SKU: \(.sku.name)"' 2>/dev/null
        fi
    done

    ########## KEY VAULT — SOFT DELETE, PURGE PROTECTION, KEY ROTATION [T1552] ##########
    print_subsection "Key Vault — Soft Delete, Purge Protection & Key Rotation [MITRE T1552]"
    : > "$outdir/keyvault-issues.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az keyvault list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.properties.enableSoftDelete)\t\(.properties.enablePurgeProtection)"' \
            2>/dev/null | \
        while IFS=$'\t' read -r kv_name rg soft_del purge_prot; do
            [[ -z "$kv_name" ]] && continue
            print_info "Key Vault '$kv_name' — SoftDelete=$soft_del | PurgeProtection=$purge_prot"

            if [[ "$soft_del" != "true" ]]; then
                print_finding_with_technique high "T1552" \
                    "Key Vault '$kv_name' (RG: $rg, Sub: $sub_id) has Soft Delete DISABLED"
                echo "SOFT_DELETE_DISABLED | $sub_id | $kv_name" >> "$outdir/keyvault-issues.txt"
            fi

            if [[ "$purge_prot" != "true" ]]; then
                print_finding_with_technique high "T1552" \
                    "Key Vault '$kv_name' (RG: $rg, Sub: $sub_id) has Purge Protection DISABLED"
                echo "PURGE_PROTECTION_DISABLED | $sub_id | $kv_name" >> "$outdir/keyvault-issues.txt"
            fi

            # Check key rotation policies
            local keys
            keys=$(az keyvault key list --vault-name "$kv_name" --output json 2>/dev/null)
            echo "$keys" | jq -r '.[]? | .name' 2>/dev/null | \
            while read -r key_name; do
                [[ -z "$key_name" ]] && continue
                local rot_policy
                rot_policy=$(az keyvault key rotation-policy show \
                    --vault-name "$kv_name" --name "$key_name" --output json 2>/dev/null)
                local rot_enabled
                rot_enabled=$(echo "$rot_policy" | jq -r '.lifetimeActions[]? | select(.action.type=="Rotate") | .trigger.timeAfterCreate // .trigger.timeBeforeExpiry' 2>/dev/null)
                if [[ -z "$rot_enabled" ]]; then
                    print_finding_with_technique medium "T1552" \
                        "Key Vault '$kv_name' key '$key_name' (Sub: $sub_id) has NO automatic rotation policy"
                    echo "NO_KEY_ROTATION | $sub_id | $kv_name | $key_name" >> "$outdir/keyvault-issues.txt"
                fi
            done

            # Check certificate expiry
            local certs
            certs=$(az keyvault certificate list --vault-name "$kv_name" --output json 2>/dev/null)
            echo "$certs" | jq -r '.[]? | "\(.name)\t\(.attributes.expires)"' 2>/dev/null | \
            while IFS=$'\t' read -r cert_name exp_date; do
                [[ -z "$cert_name" || -z "$exp_date" ]] && continue
                local exp_epoch
                exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null || \
                            date -j -f "%Y-%m-%dT%H:%M:%SZ" "$exp_date" +%s 2>/dev/null || echo 0)
                local days_until_exp=$(( (exp_epoch - $(date +%s)) / 86400 ))
                if [[ "$days_until_exp" -lt 30 && "$days_until_exp" -gt 0 ]]; then
                    print_finding_with_technique high "T1552" \
                        "Key Vault '$kv_name' certificate '$cert_name' EXPIRES IN $days_until_exp days (Sub: $sub_id)"
                    echo "CERT_EXPIRING | $sub_id | $kv_name | $cert_name | DaysLeft=$days_until_exp" >> "$outdir/keyvault-issues.txt"
                elif [[ "$days_until_exp" -le 0 ]]; then
                    print_finding_with_technique critical "T1552" \
                        "Key Vault '$kv_name' certificate '$cert_name' IS EXPIRED (Sub: $sub_id)"
                    echo "CERT_EXPIRED | $sub_id | $kv_name | $cert_name" >> "$outdir/keyvault-issues.txt"
                fi
            done
        done
    done

    ########## STORAGE ACCOUNT — ENCRYPTION & HTTPS [T1552] ##########
    print_subsection "Storage Accounts — Encryption, HTTPS-only & TLS Version [MITRE T1552]"
    : > "$outdir/storage-issues.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az storage account list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.enableHttpsTrafficOnly)\t\(.minimumTlsVersion)\t\(.encryption.keySource)"' \
            2>/dev/null | \
        while IFS=$'\t' read -r sa_name rg https_only min_tls key_source; do
            [[ -z "$sa_name" ]] && continue

            if [[ "$https_only" != "true" ]]; then
                print_finding_with_technique high "T1552" \
                    "Storage account '$sa_name' (RG: $rg, Sub: $sub_id) does NOT enforce HTTPS-only traffic"
                echo "HTTP_NOT_ENFORCED | $sub_id | $sa_name" >> "$outdir/storage-issues.txt"
            fi

            if [[ "$min_tls" == "TLS1_0" || "$min_tls" == "TLS1_1" ]]; then
                print_finding_with_technique high "T1552" \
                    "Storage account '$sa_name' (RG: $rg, Sub: $sub_id) minimum TLS is $min_tls (CIS requires TLS1_2)"
                echo "WEAK_TLS | $sub_id | $sa_name | $min_tls" >> "$outdir/storage-issues.txt"
            fi

            if [[ "$key_source" != "Microsoft.Keyvault" ]]; then
                print_finding_info "Storage account '$sa_name' (Sub: $sub_id) uses Platform-Managed Keys (PMK), not CMK — review if CMK required"
            fi
        done
    done

    ########## AZURE SQL — TDE, AUDIT, ADVANCED THREAT PROTECTION ##########
    print_subsection "Azure SQL — TDE, Auditing & Advanced Threat Protection"
    : > "$outdir/sql-issues.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az sql server list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)"' 2>/dev/null | \
        while IFS=$'\t' read -r srv_name rg; do
            [[ -z "$srv_name" ]] && continue

            # Check TDE on databases
            az sql db list --server "$srv_name" --resource-group "$rg" \
                --output json 2>/dev/null | \
            jq -r '.[]? | select(.name!="master") | .name' 2>/dev/null | \
            while read -r db_name; do
                local tde_status
                tde_status=$(az sql db tde show \
                    --server "$srv_name" --resource-group "$rg" \
                    --database "$db_name" --output json 2>/dev/null | \
                    jq -r '.state // "Unknown"')
                if [[ "$tde_status" != "Enabled" ]]; then
                    print_finding_with_technique high "T1530" \
                        "SQL Server '$srv_name' DB '$db_name' (Sub: $sub_id) TDE is $tde_status — data at rest not encrypted"
                    echo "TDE_DISABLED | $sub_id | $srv_name | $db_name" >> "$outdir/sql-issues.txt"
                fi
            done

            # Check auditing
            local audit_policy
            audit_policy=$(az sql server audit-policy show \
                --name "$srv_name" --resource-group "$rg" --output json 2>/dev/null)
            local audit_state
            audit_state=$(echo "$audit_policy" | jq -r '.state // "Disabled"')
            if [[ "$audit_state" != "Enabled" ]]; then
                print_finding_with_technique high "T1562.008" \
                    "SQL Server '$srv_name' (RG: $rg, Sub: $sub_id) auditing is $audit_state"
                echo "AUDIT_DISABLED | $sub_id | $srv_name" >> "$outdir/sql-issues.txt"
            fi

            # Check Advanced Threat Protection
            local atp
            atp=$(az security atp sql server show \
                --server "$srv_name" --resource-group "$rg" --output json 2>/dev/null)
            local atp_state
            atp_state=$(echo "$atp" | jq -r '.isEnabled // false')
            if [[ "$atp_state" != "true" ]]; then
                print_finding_medium "SQL Server '$srv_name' (Sub: $sub_id) Advanced Threat Protection is not enabled"
            fi

            # Check minimum TLS
            local sql_min_tls
            sql_min_tls=$(az sql server show \
                --name "$srv_name" --resource-group "$rg" \
                --query "minimalTlsVersion" --output tsv 2>/dev/null)
            if [[ "$sql_min_tls" == "1.0" || "$sql_min_tls" == "1.1" ]]; then
                print_finding_high "SQL Server '$srv_name' (Sub: $sub_id) minimum TLS version is $sql_min_tls"
                echo "WEAK_TLS | $sub_id | $srv_name | TLS=$sql_min_tls" >> "$outdir/sql-issues.txt"
            fi
        done
    done

    ########## DISK ENCRYPTION ##########
    print_subsection "VM Disk Encryption (Azure Disk Encryption / EncryptionAtHost)"
    : > "$outdir/unencrypted-disks.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az vm list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.id)\t\(.securityProfile.encryptionAtHost)"' \
            2>/dev/null | \
        while IFS=$'\t' read -r vm_name rg vm_id enc_at_host; do
            [[ -z "$vm_name" ]] && continue

            # Check EncryptionAtHost
            if [[ "$enc_at_host" != "true" ]]; then
                # Check Azure Disk Encryption via disk status
                local os_disk_enc
                os_disk_enc=$(az vm show \
                    --name "$vm_name" --resource-group "$rg" \
                    --query "storageProfile.osDisk.encryptionSettings.enabled" \
                    --output tsv 2>/dev/null)
                if [[ "$os_disk_enc" != "true" ]]; then
                    echo "SUB=$sub_id | VM=$vm_name | RG=$rg | EncryptionAtHost=$enc_at_host | ADE=false" \
                        >> "$outdir/unencrypted-disks.txt"
                    print_finding_high \
                        "VM '$vm_name' (RG: $rg, Sub: $sub_id) has NO disk encryption (EncryptionAtHost=false, ADE=false)"
                fi
            fi
        done
    done

    ########## NSG FLOW LOGS [T1562.008] ##########
    print_subsection "NSG Flow Logs Coverage [MITRE T1562.008]"
    : > "$outdir/nsgs-no-flowlogs.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az network watcher list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.location)\t\(.resourceGroup)\t\(.name)"' 2>/dev/null | \
        while IFS=$'\t' read -r location watcher_rg watcher_name; do
            local flow_logs
            flow_logs=$(az network watcher flow-log list \
                --location "$location" --output json 2>/dev/null)
            if [[ "$flow_logs" == "[]" || -z "$flow_logs" ]]; then
                echo "SUB=$sub_id | Location=$location | NO FLOW LOGS CONFIGURED" \
                    >> "$outdir/nsgs-no-flowlogs.txt"
                print_finding_with_technique high "T1562.008" \
                    "No NSG Flow Logs configured in location '$location' (Sub: $sub_id)"
            else
                # Verify flow logs are enabled
                echo "$flow_logs" | jq -r '.[]? | select(.enabled==false) | .name' 2>/dev/null | \
                while read -r fl_name; do
                    print_finding_with_technique high "T1562.008" \
                        "Flow log '$fl_name' in '$location' (Sub: $sub_id) is DISABLED"
                    echo "DISABLED | $sub_id | $location | $fl_name" >> "$outdir/nsgs-no-flowlogs.txt"
                done
            fi
        done
    done

    ########## AZURE BACKUP POLICIES ##########
    print_subsection "Azure Backup Policies"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local vaults
        vaults=$(az backup vault list --output json 2>/dev/null)
        local vault_count
        vault_count=$(echo "$vaults" | jq 'length' 2>/dev/null || echo 0)
        if [[ "$vault_count" -eq 0 ]]; then
            print_finding_medium "No Azure Backup/Recovery Services Vaults found in sub $sub_id"
        else
            print_info "$vault_count Recovery Services Vault(s) found in sub $sub_id"
            echo "$vaults" | jq -r '.[]? | "  → \(.name) | RG: \(.resourceGroup)"' 2>/dev/null
        fi
    done

    ########## AKS — RBAC, NETWORK POLICY, API SERVER ACCESS ##########
    print_subsection "AKS Clusters — RBAC, Network Policy & Public API Server"
    : > "$outdir/aks-issues.txt"
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        az aks list --output json 2>/dev/null | \
        jq -c '.[]?' 2>/dev/null | \
        while read -r cluster; do
            local aks_name rg rbac_enabled net_policy api_public
            aks_name=$(echo "$cluster" | jq -r '.name')
            rg=$(echo "$cluster" | jq -r '.resourceGroup')
            rbac_enabled=$(echo "$cluster" | jq -r '.enableRbac // false')
            net_policy=$(echo "$cluster" | jq -r '.networkProfile.networkPolicy // "none"')
            api_public=$(echo "$cluster" | jq -r '.apiServerAccessProfile.enablePrivateCluster // false')

            [[ -z "$aks_name" ]] && continue
            print_info "AKS '$aks_name' (RG: $rg, Sub: $sub_id) — RBAC=$rbac_enabled | NetPolicy=$net_policy | PrivateCluster=$api_public"

            if [[ "$rbac_enabled" != "true" ]]; then
                print_finding_with_technique critical "T1190" \
                    "AKS cluster '$aks_name' (Sub: $sub_id) has RBAC DISABLED"
                echo "RBAC_DISABLED | $sub_id | $aks_name" >> "$outdir/aks-issues.txt"
            fi

            if [[ "$net_policy" == "none" || -z "$net_policy" ]]; then
                print_finding_high "AKS cluster '$aks_name' (Sub: $sub_id) has NO network policy (pod-to-pod traffic unrestricted)"
                echo "NO_NETWORK_POLICY | $sub_id | $aks_name" >> "$outdir/aks-issues.txt"
            fi

            if [[ "$api_public" != "true" ]]; then
                print_finding_with_technique high "T1190" \
                    "AKS cluster '$aks_name' (Sub: $sub_id) API server is PUBLIC — not configured as private cluster"
                echo "PUBLIC_API_SERVER | $sub_id | $aks_name" >> "$outdir/aks-issues.txt"
            fi
        done
    done

    ########## CIS PHASE 1 — AZURE MONITOR ALERT RULES ##########
    print_subsection "CIS Azure Benchmark — Activity Log Alert Rules (CIS Section 5)"
    local cis_outfile="$outdir/cis-monitor-alerts.txt"
    : > "$cis_outfile"

    # Get all activity log alerts across subscriptions
    local all_alerts=()
    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null
        local alerts_json
        alerts_json=$(az monitor activity-log alert list --output json 2>/dev/null)
        all_alerts+=("$alerts_json")
    done
    local combined_alerts
    combined_alerts=$(printf '%s\n' "${all_alerts[@]}" | jq -s 'add // []' 2>/dev/null || echo "[]")

    local -a CIS_ALERT_CHECKS=(
        "CIS-5.1.1|Create/Update/Delete Policy Assignment|Microsoft.Authorization/policyAssignments/write|Microsoft.Authorization/policyAssignments/delete"
        "CIS-5.1.2|Create/Update/Delete Network Security Group|Microsoft.Network/networkSecurityGroups/write|Microsoft.Network/networkSecurityGroups/delete"
        "CIS-5.1.3|Create or Update SQL Server Firewall Rule|Microsoft.Sql/servers/firewallRules/write|Microsoft.Sql/servers/firewallRules/delete"
        "CIS-5.1.4|Delete Key Vault|Microsoft.KeyVault/vaults/delete"
        "CIS-5.1.5|Create or Update Security Solution|Microsoft.Security/securitySolutions/write"
        "CIS-5.1.6|Create Update or Delete SQL Server|Microsoft.Sql/servers/write|Microsoft.Sql/servers/delete"
        "CIS-5.1.7|Create or Update Public IP Address|Microsoft.Network/publicIPAddresses/write"
    )

    local cis_pass=0 cis_fail=0

    for check in "${CIS_ALERT_CHECKS[@]}"; do
        local cis_id description keywords_str
        IFS='|' read -r cis_id description keywords_str <<< "$check"

        local found=false
        for keyword in $(echo "$keywords_str" | tr '|' ' '); do
            if echo "$combined_alerts" | grep -qi "$keyword" 2>/dev/null; then
                found=true
                break
            fi
        done

        if [[ "$found" == "true" ]]; then
            print_success "[$cis_id] Alert rule configured: $description"
            echo "PASS | $cis_id | $description" >> "$cis_outfile"
            ((cis_pass++))
        else
            print_finding_medium "[$cis_id] No Activity Log alert rule found for: $description"
            echo "FAIL | $cis_id | No alert rule | $description" >> "$cis_outfile"
            ((cis_fail++))
        fi
    done

    print_info "CIS Activity Log Alert Summary: $cis_pass passed, $cis_fail failed"
    [[ $cis_fail -gt 0 ]] && \
        print_finding_medium "$cis_fail CIS monitoring control(s) missing Activity Log alert rules"

    ########## PHASE 2 — ENCRYPTION IN TRANSIT ##########
    print_subsection "Phase 2 — Encryption in Transit"
    local transit_outfile="$outdir/encryption-in-transit.txt"
    : > "$transit_outfile"

    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        # App Services / Function Apps
        az webapp list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.httpsOnly)\t\(.siteConfig.minTlsVersion)"' \
            2>/dev/null | \
        while IFS=$'\t' read -r app_name rg https_only min_tls; do
            [[ -z "$app_name" ]] && continue
            if [[ "$https_only" != "true" ]]; then
                print_finding_high "App Service '$app_name' (Sub: $sub_id) does NOT enforce HTTPS-only"
                echo "APP_NO_HTTPS | $sub_id | $app_name | httpsOnly=false" >> "$transit_outfile"
            fi
            if [[ "$min_tls" == "1.0" || "$min_tls" == "1.1" ]]; then
                print_finding_high "App Service '$app_name' (Sub: $sub_id) minimum TLS is $min_tls"
                echo "WEAK_TLS | $sub_id | $app_name | $min_tls" >> "$transit_outfile"
            fi
        done

        # Application Gateway SSL policy
        az network application-gateway list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)\t\(.sslPolicy.policyName // .sslPolicy.minProtocolVersion // "Default")"' \
            2>/dev/null | \
        while IFS=$'\t' read -r agw_name rg ssl_policy; do
            [[ -z "$agw_name" ]] && continue
            if echo "$ssl_policy" | grep -qi "AppGwSslPolicy20150501\|TLSv1_0\|TLSv1_1"; then
                print_finding_high "Application Gateway '$agw_name' (Sub: $sub_id) uses weak SSL policy: $ssl_policy"
                echo "WEAK_SSL_POLICY | $sub_id | $agw_name | $ssl_policy" >> "$transit_outfile"
            fi
        done

        # API Management TLS
        az apim list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.name)\t\(.resourceGroup)"' 2>/dev/null | \
        while IFS=$'\t' read -r apim_name rg; do
            [[ -z "$apim_name" ]] && continue
            local apim_detail
            apim_detail=$(az apim show --name "$apim_name" --resource-group "$rg" \
                --output json 2>/dev/null)
            local client_cert_enabled
            client_cert_enabled=$(echo "$apim_detail" | jq -r '.customProperties["Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10"] // "false"')
            if [[ "$client_cert_enabled" == "true" ]]; then
                print_finding_high "APIM '$apim_name' (Sub: $sub_id) has TLS 1.0 enabled for backend"
                echo "APIM_WEAK_TLS | $sub_id | $apim_name" >> "$transit_outfile"
            fi
        done
    done

    local transit_issues
    transit_issues=$(wc -l < "$transit_outfile" 2>/dev/null | tr -d ' ')
    if [[ "$transit_issues" -eq 0 ]]; then
        print_success "No encryption-in-transit misconfigurations detected"
    else
        print_info "$transit_issues encryption-in-transit issue(s) — see encryption-in-transit.txt"
    fi

    ########## PHASE 6 — SERVICE-LEVEL DIAGNOSTIC LOGGING ##########
    print_subsection "Phase 6 — Service-Level Diagnostic Logging"
    local svclog_file="$outdir/service-logging-gaps.txt"
    : > "$svclog_file"

    for sub_id in "${SUBSCRIPTION_IDS[@]}"; do
        az account set --subscription "$sub_id" 2>/dev/null

        # Storage accounts
        az storage account list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.id)\t\(.name)"' 2>/dev/null | \
        while IFS=$'\t' read -r sa_id sa_name; do
            local ds_count
            ds_count=$(az monitor diagnostic-settings list --resource "$sa_id" \
                --output json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
            [[ "$ds_count" -eq 0 ]] && \
                echo "STORAGE | $sub_id | $sa_name | NO_DIAG_SETTINGS" >> "$svclog_file"
        done

        # AKS
        az aks list --output json 2>/dev/null | \
        jq -r '.[]? | "\(.id)\t\(.name)"' 2>/dev/null | \
        while IFS=$'\t' read -r aks_id aks_name; do
            local ds_count
            ds_count=$(az monitor diagnostic-settings list --resource "$aks_id" \
                --output json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
            [[ "$ds_count" -eq 0 ]] && \
                echo "AKS | $sub_id | $aks_name | NO_DIAG_SETTINGS" >> "$svclog_file"
        done
    done

    local svclog_gap_count
    svclog_gap_count=$(wc -l < "$svclog_file" 2>/dev/null | tr -d ' ')
    if [[ "$svclog_gap_count" -gt 0 ]]; then
        print_finding_with_technique high "T1562.008" \
            "$svclog_gap_count service(s) missing diagnostic logging — see service-logging-gaps.txt"
    else
        print_success "Service-level diagnostic logging appears configured for sampled resources"
    fi
}


###############################################################################
# RUN PROWLER (Azure Provider)
###############################################################################

run_prowler() {
    print_section "RUNNING PROWLER COMPREHENSIVE SCAN (Azure Provider)"
    local outdir="$OUTPUT_DIR/07-tool-output/prowler"
    mkdir -p "$outdir"

    if command -v docker &>/dev/null; then
        print_info "Starting Prowler scan via Docker (10–30 minutes)..."
        chmod 777 "$outdir"

        docker run --rm \
            -e AZURE_CLIENT_ID="$APP_ID" \
            -e AZURE_CLIENT_SECRET="$CLIENT_SECRET" \
            -e AZURE_TENANT_ID="$TENANT_ID" \
            -v "$outdir:/home/prowler/output" \
            prowlercloud/prowler:latest azure \
            --sp-env-auth \
            --subscription-ids "${SUBSCRIPTION_IDS[@]}" \
            --output-formats csv html json-ocsf \
            --status FAIL \
            --compliance cis_2.0_azure \
            2>&1 | tee "$outdir/prowler-stdout.log" | \
            grep -E "FAIL|PASS|ERROR|WARNING|Progress|Total|Scann" || true

        print_success "Prowler scan complete → $outdir"

        local csv_file
        csv_file=$(ls -t "$outdir"/prowler-output-*.csv 2>/dev/null | head -1)
        if [[ -n "$csv_file" ]]; then
            print_info "FAIL findings by severity:"
            awk -F',' 'NR>1 && /FAIL/ {print $5}' "$csv_file" 2>/dev/null | \
                sort | uniq -c | sort -rn | head -10 || true
        fi
    elif command -v prowler &>/dev/null; then
        print_warn "Using local Prowler installation..."
        prowler azure \
            --sp-env-auth \
            --subscription-ids "${SUBSCRIPTION_IDS[@]}" \
            --output-directory "$outdir" \
            --output-formats csv html \
            --status FAIL \
            2>&1 | tee "$outdir/prowler-stdout.log" | grep -E "FAIL|PASS|Progress|Total" || true
        print_success "Prowler scan complete → $outdir"
    else
        print_warn "Docker not available — skipping Prowler."
        print_warn "To enable: install Docker and run: docker pull prowlercloud/prowler:latest"
    fi
}


###############################################################################
# RUN SCOUTSUITE (Azure Provider)
###############################################################################

run_scoutsuite() {
    print_section "RUNNING SCOUTSUITE (Azure Provider)"
    local outdir="$OUTPUT_DIR/07-tool-output/scoutsuite"
    mkdir -p "$outdir"

    if command -v scout &>/dev/null; then
        print_info "Starting ScoutSuite Azure scan..."
        scout azure \
            --cli \
            --tenant "$TENANT_ID" \
            --subscription-ids "${SUBSCRIPTION_IDS[@]}" \
            --report-dir "$outdir" \
            --no-browser \
            2>&1 | tee "$outdir/scout-stdout.log"
        print_success "ScoutSuite scan complete → $outdir"
    else
        print_warn "ScoutSuite not available — run: pip3 install scoutsuite"
    fi
}


###############################################################################
# PHASE 8 — THREAT MODELING
###############################################################################

run_threat_modeling() {
    CURRENT_MODULE="PHASE 8: THREAT MODELING"
    print_section "PHASE 8: THREAT MODELING"
    local outdir="$OUTPUT_DIR/reports"
    local tm_file="$outdir/threat-models.txt"
    : > "$tm_file"

    _count_lines() { wc -l < "$1" 2>/dev/null | tr -d ' '; }
    _risk_label() {
        local score=$1
        if   [[ $score -ge 7 ]]; then echo "CRITICAL"
        elif [[ $score -ge 5 ]]; then echo "HIGH"
        elif [[ $score -ge 3 ]]; then echo "MEDIUM"
        else echo "LOW"
        fi
    }
    _print_risk() {
        case "$1" in
            CRITICAL) echo -e "  ${RED}${BOLD}Risk Level: CRITICAL${NC}" ;;
            HIGH)     echo -e "  ${RED}Risk Level: HIGH${NC}" ;;
            MEDIUM)   echo -e "  ${YELLOW}Risk Level: MEDIUM${NC}" ;;
            LOW)      echo -e "  ${GREEN}Risk Level: LOW${NC}" ;;
        esac
    }

    # ── Threat Model 1: Credential Compromise Path ──
    print_subsection "Threat Model 1 — Credential Compromise Path [TA0006 → TA0001]"
    local no_mfa_count ga_count no_ca_count tm1_score tm1_risk tm1_narrative
    no_mfa_count=$(_count_lines "$OUTPUT_DIR/04-access/users-no-mfa.txt")
    ga_count=$(jq '.value | length' "$OUTPUT_DIR/04-access/global-admins.json" 2>/dev/null || echo 0)
    no_ca_count=$(jq 'if .value | length == 0 then 1 else 0 end' \
        "$OUTPUT_DIR/04-access/conditional-access-policies.json" 2>/dev/null || echo 1)

    tm1_score=0
    [[ $no_mfa_count -gt 10 ]] && ((tm1_score+=3))
    [[ $no_mfa_count -gt 0 && $no_mfa_count -le 10 ]] && ((tm1_score+=2))
    [[ $ga_count -gt 5 ]] && ((tm1_score+=2))
    [[ $no_ca_count -gt 0 ]] && ((tm1_score+=3))
    tm1_risk=$(_risk_label $tm1_score)

    tm1_narrative="Credential compromise indicators:"
    [[ $no_mfa_count -gt 0 ]] && tm1_narrative+=" $no_mfa_count user(s) without MFA (T1078.004)."
    [[ $ga_count -gt 5 ]] && tm1_narrative+=" Excessive Global Admins: $ga_count."
    [[ $no_ca_count -gt 0 ]] && tm1_narrative+=" No/disabled Conditional Access policies."
    [[ $tm1_score -lt 2 ]] && tm1_narrative=" No significant credential compromise indicators."

    _print_risk "$tm1_risk"
    print_info "MITRE: T1078.004 → T1110 → TA0006 → TA0001"
    print_info "$tm1_narrative"
    { echo "=== THREAT MODEL 1: Credential Compromise Path ==="
      echo "Risk: $tm1_risk | Score: $tm1_score/10"
      echo "MITRE Chain: T1078.004 → T1110 → TA0006 → TA0001"
      echo "Narrative: $tm1_narrative"
      echo ""
    } >> "$tm_file"
    [[ "$tm1_risk" =~ ^(CRITICAL|HIGH)$ ]] && \
        print_finding_with_technique high "T1078.004" \
            "Threat Model 1: Credential compromise path rated $tm1_risk"

    # ── Threat Model 2: Data Exfiltration Path ──
    print_subsection "Threat Model 2 — Data Exfiltration Path [T1530 → TA0010]"
    local public_blobs public_dbs public_snapshots tm2_score tm2_risk tm2_narrative
    public_blobs=$(_count_lines "$OUTPUT_DIR/03-visibility/public-blob-containers.txt")
    public_dbs=$(_count_lines "$OUTPUT_DIR/03-visibility/public-databases.txt")
    public_snapshots=$(_count_lines "$OUTPUT_DIR/03-visibility/public-snapshots.txt")

    tm2_score=0
    [[ $public_blobs -gt 0 ]]    && ((tm2_score+=3))
    [[ $public_dbs -gt 0 ]]      && ((tm2_score+=3))
    [[ $public_snapshots -gt 0 ]] && ((tm2_score+=2))
    tm2_risk=$(_risk_label $tm2_score)

    tm2_narrative="Data exfiltration indicators:"
    [[ $public_blobs -gt 0 ]]     && tm2_narrative+=" $public_blobs storage account(s) with public blob access (T1530)."
    [[ $public_dbs -gt 0 ]]       && tm2_narrative+=" $public_dbs database(s) with public network access (T1190)."
    [[ $public_snapshots -gt 0 ]] && tm2_narrative+=" $public_snapshots publicly accessible disk snapshot(s) (T1530)."
    [[ $tm2_score -lt 2 ]]        && tm2_narrative=" No critical public data exposure paths identified."

    _print_risk "$tm2_risk"
    print_info "MITRE: T1530 → T1190 → TA0010"
    print_info "$tm2_narrative"
    { echo "=== THREAT MODEL 2: Data Exfiltration Path ==="
      echo "Risk: $tm2_risk | Score: $tm2_score/10"
      echo "MITRE Chain: T1530 → T1190 → TA0009 → TA0010"
      echo "Narrative: $tm2_narrative"
      echo ""
    } >> "$tm_file"
    [[ "$tm2_risk" =~ ^(CRITICAL|HIGH)$ ]] && \
        print_finding_with_technique high "T1530" \
            "Threat Model 2: Data exfiltration path rated $tm2_risk"

    # ── Threat Model 3: Lateral Movement Risk ──
    print_subsection "Threat Model 3 — Lateral Movement Risk [T1199 → TA0008]"
    local no_flowlog_count lighthouse_count peering_count tm3_score tm3_risk tm3_narrative
    no_flowlog_count=$(_count_lines "$OUTPUT_DIR/06-controls/nsgs-no-flowlogs.txt")
    lighthouse_count=$(_count_lines "$OUTPUT_DIR/05-trust/lighthouse-delegations.txt")
    peering_count=$(_count_lines "$OUTPUT_DIR/05-trust/vnet-peerings.txt")

    tm3_score=0
    [[ $no_flowlog_count -gt 0 ]]  && ((tm3_score+=2))
    [[ $lighthouse_count -gt 0 ]]  && ((tm3_score+=2))
    [[ $peering_count -gt 5 ]]     && ((tm3_score+=2))
    tm3_risk=$(_risk_label $tm3_score)

    tm3_narrative="Lateral movement indicators:"
    [[ $no_flowlog_count -gt 0 ]] && tm3_narrative+=" $no_flowlog_count location(s) without NSG flow logs."
    [[ $lighthouse_count -gt 0 ]] && tm3_narrative+=" $lighthouse_count Lighthouse delegation(s) (cross-tenant access)."
    [[ $peering_count -gt 0 ]]    && tm3_narrative+=" $peering_count VNet peering(s) detected."
    [[ $tm3_score -lt 2 ]]        && tm3_narrative=" No significant lateral movement indicators."

    _print_risk "$tm3_risk"
    print_info "MITRE: T1199 → T1078 → TA0008"
    print_info "$tm3_narrative"
    { echo "=== THREAT MODEL 3: Lateral Movement Risk ==="
      echo "Risk: $tm3_risk | Score: $tm3_score/10"
      echo "MITRE Chain: T1199 → T1078.004 → TA0008"
      echo "Narrative: $tm3_narrative"
      echo ""
    } >> "$tm_file"
    [[ "$tm3_risk" =~ ^(CRITICAL|HIGH)$ ]] && \
        print_finding_with_technique high "T1199" \
            "Threat Model 3: Lateral movement risk rated $tm3_risk"

    # ── Threat Model 4: Persistence & Defense Evasion ──
    print_subsection "Threat Model 4 — Persistence & Defense Evasion [TA0003 → TA0005]"
    local diag_gaps sentinel_count kv_issues tm4_score tm4_risk tm4_narrative
    diag_gaps=$(_count_lines "$OUTPUT_DIR/06-controls/diagnostic-settings-gaps.txt")
    sentinel_count=$(ls "$OUTPUT_DIR/06-controls/security-workspace-"*.json 2>/dev/null | wc -l | tr -d ' ')
    kv_issues=$(_count_lines "$OUTPUT_DIR/06-controls/keyvault-issues.txt")

    tm4_score=0
    [[ $diag_gaps -gt 5 ]]    && ((tm4_score+=3))
    [[ $sentinel_count -eq 0 ]] && ((tm4_score+=2))
    [[ $kv_issues -gt 5 ]]    && ((tm4_score+=2))
    tm4_risk=$(_risk_label $tm4_score)

    tm4_narrative="Persistence and evasion indicators:"
    [[ $diag_gaps -gt 0 ]]      && tm4_narrative+=" $diag_gaps resource(s) missing diagnostic settings (T1562.008)."
    [[ $sentinel_count -eq 0 ]] && tm4_narrative+=" Microsoft Sentinel not detected — no SIEM coverage."
    [[ $kv_issues -gt 0 ]]      && tm4_narrative+=" $kv_issues Key Vault misconfiguration(s) (T1552)."
    [[ $tm4_score -lt 2 ]]      && tm4_narrative=" Detection and logging controls appear largely in place."

    _print_risk "$tm4_risk"
    print_info "MITRE: T1562.008 → T1552 → TA0003 → TA0005"
    print_info "$tm4_narrative"
    { echo "=== THREAT MODEL 4: Persistence & Defense Evasion ==="
      echo "Risk: $tm4_risk | Score: $tm4_score/10"
      echo "MITRE Chain: T1562.008 → T1552 → TA0003 → TA0005"
      echo "Narrative: $tm4_narrative"
      echo ""
    } >> "$tm_file"
    [[ "$tm4_risk" =~ ^(CRITICAL|HIGH)$ ]] && \
        print_finding_with_technique high "T1562.008" \
            "Threat Model 4: Persistence/evasion risk rated $tm4_risk"

    print_success "Threat modeling complete — reports/threat-models.txt"
}


###############################################################################
# RESOURCE INVENTORY REPORT
###############################################################################

generate_resource_inventory() {
    local inv_file="$OUTPUT_DIR/reports/resource-inventory.txt"
    print_info "Building resource inventory report..."
    : > "$inv_file"

    {
    echo "============================================================"
    echo " AZURE CLOUD CONFIGURATION REVIEW — AFFECTED RESOURCE INVENTORY"
    echo " Client: $CLIENT_NAME  |  Tenant: $TENANT_ID"
    echo " Generated: $(date)"
    echo "============================================================"
    echo ""
    echo "── VMs WITH PUBLIC IPs ───────────────────────────────────────"
    cat "$OUTPUT_DIR/03-visibility/public-vms.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── NSG RULES OPEN TO INTERNET [T1190] ───────────────────────"
    cat "$OUTPUT_DIR/03-visibility/open-nsg-rules.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── STORAGE ACCOUNTS WITH PUBLIC BLOB ACCESS [T1530] ─────────"
    cat "$OUTPUT_DIR/03-visibility/public-blob-containers.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── STORAGE ACCOUNT CONFIG ISSUES ────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/storage-issues.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── DATABASES WITH PUBLIC NETWORK ACCESS [T1190] ─────────────"
    cat "$OUTPUT_DIR/03-visibility/public-databases.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── PUBLIC DISK SNAPSHOTS [T1530] ────────────────────────────"
    cat "$OUTPUT_DIR/03-visibility/public-snapshots.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── ANONYMOUS FUNCTION INVOCATIONS [T1190] ───────────────────"
    cat "$OUTPUT_DIR/03-visibility/anonymous-functions.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── FUNCTION APP RUNTIME / APP SETTING ISSUES [T1552] ────────"
    cat "$OUTPUT_DIR/03-visibility/function-app-findings.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── USERS WITHOUT MFA [T1078.004] ────────────────────────────"
    cat "$OUTPUT_DIR/04-access/users-no-mfa.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── STALE ACCOUNTS (>90 DAYS NO SIGN-IN) ─────────────────────"
    cat "$OUTPUT_DIR/04-access/stale-accounts.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── OVERPRIVILEGED SERVICE PRINCIPALS [T1078.004] ────────────"
    cat "$OUTPUT_DIR/04-access/overprivileged-sps.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── AZURE LIGHTHOUSE DELEGATIONS [T1199] ─────────────────────"
    cat "$OUTPUT_DIR/05-trust/lighthouse-delegations.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── VNET PEERING CONNECTIONS ─────────────────────────────────"
    cat "$OUTPUT_DIR/05-trust/vnet-peerings.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── DIAGNOSTIC SETTINGS GAPS [T1562.008] ─────────────────────"
    cat "$OUTPUT_DIR/06-controls/diagnostic-settings-gaps.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── NSG FLOW LOG GAPS [T1562.008] ────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/nsgs-no-flowlogs.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── KEY VAULT ISSUES [T1552] ─────────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/keyvault-issues.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── AZURE SQL ISSUES ─────────────────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/sql-issues.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── VMs WITHOUT DISK ENCRYPTION ──────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/unencrypted-disks.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── AKS CLUSTER ISSUES ───────────────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/aks-issues.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── ENCRYPTION IN TRANSIT ISSUES ─────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/encryption-in-transit.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── SERVICE LOGGING GAPS ─────────────────────────────────────"
    cat "$OUTPUT_DIR/06-controls/service-logging-gaps.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── CIS MONITOR ALERT RULE GAPS ──────────────────────────────"
    grep "^FAIL" "$OUTPUT_DIR/06-controls/cis-monitor-alerts.txt" 2>/dev/null \
        | sed 's/^/  /' || echo "  None found"
    echo ""
    echo "── INTERNET-FACING LOAD BALANCERS ───────────────────────────"
    cat "$OUTPUT_DIR/03-visibility/public-load-balancers.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "── INTERNET-FACING API MANAGEMENT ───────────────────────────"
    cat "$OUTPUT_DIR/03-visibility/public-apim.txt" 2>/dev/null || echo "  None found"
    echo ""
    echo "============================================================"
    echo " END OF RESOURCE INVENTORY"
    echo "============================================================"
    } >> "$inv_file"

    print_success "Resource inventory: $inv_file"
}


###############################################################################
# EXECUTIVE SUMMARY
###############################################################################

generate_summary() {
    print_section "GENERATING EXECUTIVE SUMMARY REPORT"
    local summary="$OUTPUT_DIR/reports/EXECUTIVE_SUMMARY.md"
    local subscription_list
    subscription_list=$(printf '%s, ' "${SUBSCRIPTION_IDS[@]}" | sed 's/, $//')

    cat > "$summary" << SUMMARY_EOF
# Azure Cloud Configuration Review - Executive Summary

**Client:** $CLIENT_NAME
**Tenant ID:** $TENANT_ID
**App ID (Assessor):** $APP_ID
**Subscriptions:** $subscription_list
**Assessment Date:** $(date)
**Methodology:** OSSTMM v3 Posture Review (Cloud-Adapted) + CIS Azure Benchmark

---

## Findings Counter

| Severity | Count |
|----------|-------|
| 🚨 Critical | $FINDINGS_CRITICAL |
| ⚠ High     | $FINDINGS_HIGH |
| ▲ Medium   | $FINDINGS_MEDIUM |
| ℹ Info     | $FINDINGS_INFO |

---

## Key Artifacts

| Artifact | Path |
|----------|------|
| Posture Data | \`01-posture/\` |
| Logistics | \`02-logistics/\` |
| Visibility Audit | \`03-visibility/\` |
| Access Verification | \`04-access/\` |
| Trust Verification | \`05-trust/\` |
| Controls Verification | \`06-controls/\` |
| Prowler Report | \`07-tool-output/prowler/\` |
| ScoutSuite HTML | \`07-tool-output/scoutsuite/\` |

---

## Immediate Items to Validate Manually

1. **MFA Coverage** → \`04-access/users-no-mfa.txt\`
2. **Public Exposure** → \`03-visibility/\`
3. **Logging & Monitoring** → \`06-controls/diagnostic-settings-gaps.txt\`
4. **Trust Relationships** → \`05-trust/\`
5. **Key Vault Security** → \`06-controls/keyvault-issues.txt\`
6. **Conditional Access** → \`04-access/conditional-access-policies.json\`

---

## MITRE ATT&CK for Cloud Coverage Map

| Tactic | Technique | ID | Checked By |
|--------|-----------|-----|------------|
| Initial Access | Valid Cloud Accounts | T1078.004 | MFA checks, CA policies, stale accounts |
| Initial Access | Exploit Public-Facing Application | T1190 | NSG rules, public SQL, AKS API server |
| Initial Access | Trusted Relationship | T1199 | Cross-tenant access, Lighthouse, VNet peering |
| Credential Access | Unsecured Credentials | T1552 | Key Vault config, Function App settings |
| Credential Access | Cloud Instance Metadata API | T1552.005 | Azure IMDS policy enforcement |
| Collection | Data from Cloud Storage | T1530 | Public blobs, public snapshots |
| Defense Evasion | Disable Cloud Logs | T1562.008 | Diagnostic settings, NSG flow logs, Activity Log |
| Impact | Supply Chain Compromise | T1195.002 | Function App deprecated runtimes |

---

## Frameworks Coverage

- **CSA Cloud Controls Matrix (CCM):** IAM, Data Security, Logging, Infrastructure Security
- **CIS Benchmark for Azure:** Identity (Section 1), Storage (2), Database (4), Logging (5), Networking (6)
- **MITRE ATT&CK for Cloud:** See table above
- **Azure Well-Architected Security Pillar:** Identity, Networking, Data, Apps, Governance

---

*Generated by Azure Cloud Configuration Review v${SCRIPT_VERSION}*
SUMMARY_EOF

    print_success "Summary written to: $summary"

    cat > "$OUTPUT_DIR/reports/QUICK_REFERENCE.txt" << QREF_EOF
AZURE CLOUD CONFIGURATION REVIEW - QUICK REFERENCE
===================================================
Client:        $CLIENT_NAME
Tenant ID:     $TENANT_ID
App ID:        $APP_ID
Subscriptions: $subscription_list
Output Dir:    $OUTPUT_DIR

FINDINGS:
  Critical: $FINDINGS_CRITICAL
  High:     $FINDINGS_HIGH
  Medium:   $FINDINGS_MEDIUM
  Info:     $FINDINGS_INFO

USEFUL COMMANDS:
  az login --service-principal -u $APP_ID -p <SECRET> --tenant $TENANT_ID
  az account set --subscription <SUBSCRIPTION_ID>
QREF_EOF

    print_success "Quick reference: $OUTPUT_DIR/reports/QUICK_REFERENCE.txt"
}


###############################################################################
# HTML REPORT GENERATION
###############################################################################

generate_html_report() {
    print_section "GENERATING HTML ASSESSMENT REPORT"
    local html_file="$OUTPUT_DIR/reports/assessment-report.html"
    print_info "Building interactive HTML report..."

    local sub_list
    sub_list=$(printf '%s,' "${SUBSCRIPTION_IDS[@]}" | sed 's/,$//')

    python3 "$(dirname "$0")/azure_html_report_generator.py" \
        "$OUTPUT_DIR" \
        "$CLIENT_NAME" \
        "$TENANT_ID" \
        "$APP_ID" \
        "$SCRIPT_VERSION" \
        "$FINDINGS_CRITICAL" \
        "$FINDINGS_HIGH" \
        "$FINDINGS_MEDIUM" \
        "$FINDINGS_INFO" \
        "$TIMESTAMP" \
        "$sub_list"

    if [[ -f "$html_file" ]]; then
        print_success "HTML report: $html_file"
        if command -v xdg-open &>/dev/null; then
            xdg-open "$html_file" &>/dev/null &
        elif command -v open &>/dev/null; then
            open "$html_file" &>/dev/null &
        fi
    else
        print_warn "HTML report generation failed — check that azure_html_report_generator.py is in the same directory"
    fi
}


###############################################################################
# FINAL DISPLAY
###############################################################################

print_final_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}==============================================================================${NC}"
    echo -e "${GREEN}${BOLD}                    ASSESSMENT COMPLETE                                      ${NC}"
    echo -e "${GREEN}${BOLD}==============================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}Output Directory:${NC}  $OUTPUT_DIR"
    echo ""
    echo -e "  ${BOLD}Findings Summary:${NC}"
    echo -e "    🚨 Critical: ${RED}$FINDINGS_CRITICAL${NC}"
    echo -e "    ⚠  High:     ${RED}$FINDINGS_HIGH${NC}"
    echo -e "    ▲  Medium:   ${YELLOW}$FINDINGS_MEDIUM${NC}"
    echo -e "    ℹ  Info:     ${CYAN}$FINDINGS_INFO${NC}"
    echo ""
    echo -e "  ${BOLD}Next Steps:${NC}"
    echo -e "    1. HTML Report:   ${CYAN}$OUTPUT_DIR/reports/assessment-report.html${NC}"
    echo -e "    2. Inventory:     ${CYAN}$OUTPUT_DIR/reports/resource-inventory.txt${NC}"
    echo -e "    3. Summary:       ${CYAN}$OUTPUT_DIR/reports/EXECUTIVE_SUMMARY.md${NC}"
    echo -e "    4. Prowler:       ${CYAN}$OUTPUT_DIR/07-tool-output/prowler/*.html${NC}"
    echo -e "    5. ScoutSuite:    ${CYAN}$OUTPUT_DIR/07-tool-output/scoutsuite/*.html${NC}"
    echo -e "    6. Findings Log:  ${CYAN}$OUTPUT_DIR/reports/findings.log${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}==============================================================================${NC}"
}


###############################################################################
# MAIN EXECUTION
###############################################################################

main() {
    print_banner
    echo -e "${YELLOW}${BOLD}This script performs a READ-ONLY Azure Cloud Configuration Review.${NC}"
    echo -e "${YELLOW}Expected runtime: 30–90 minutes depending on environment size.${NC}"
    echo ""
    read -rp "Press ENTER to continue, or Ctrl+C to abort..."

    check_dependencies
    prompt_credentials

    module_posture_review
    module_logistics
    module_visibility_audit
    module_access_verification
    module_trust_verification
    module_controls_verification

    run_prowler
    run_scoutsuite

    run_threat_modeling
    generate_resource_inventory
    generate_summary
    generate_html_report
    print_final_summary
}

main "$@"
