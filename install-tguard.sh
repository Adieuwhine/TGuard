#!/bin/bash

MANAGER_PATH="/opt/tguard-manager.sh"
LINK_PATH="/usr/local/bin/tguard"
MANUAL_FILE="/opt/tguard-manual.list"

rm -f "$MANAGER_PATH" "$LINK_PATH"

cat > "$MANAGER_PATH" << 'EOF'
#!/bin/bash
set -u

VERSION="0.2"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TG_REPO="Adieuwhine/TGuard"
TG_BINARY="tguard"
TG_INSTALL_DIR="/opt"
TG_BIN_PATH="${TG_INSTALL_DIR}/${TG_BINARY}"
TG_BIN_VERSIONED="${TG_INSTALL_DIR}/${TG_BINARY}-v${VERSION}"
TG_LATEST_URL="https://github.com/${TG_REPO}/releases/latest/download"
TG_DEV_MODE=false

LIST_ANTISCAN="https://raw.githubusercontent.com/${TG_REPO}/main/lists/antiscan.list"
LIST_GOV="https://raw.githubusercontent.com/${TG_REPO}/main/lists/gov.list"
LIST_MISC="https://raw.githubusercontent.com/${TG_REPO}/main/lists/misc.list"
MANUAL_FILE="/opt/tguard-manual.list"

REMOVE_LOGS=false
FORCE_YES=false

check_root() {
    [[ $EUID -ne 0 ]] && { clear; echo -e "${RED}Запуск только от root!${NC}"; exit 1; }
}

check_firewall_safety() {
    echo -e "${BLUE}▸ Проверка конфигурации Firewall...${NC}"
    if command -v ufw >/dev/null; then
        UFW_STATUS=$(ufw status | grep "Status" | awk '{print $2}')
        UFW_RULES=$(ufw show added 2>/dev/null)
        if [[ "$UFW_STATUS" == "inactive" ]]; then
            if [[ "$UFW_RULES" != *"22"* ]] && [[ "$UFW_RULES" != *"SSH"* ]] && [[ "$UFW_RULES" != *"OpenSSH"* ]]; then
                echo -e "\n${RED}⛔ АВАРИЙНАЯ ОСТАНОВКА!${NC}"
                echo -e "${YELLOW}UFW выключен и нет правил SSH.${NC}"
                echo "Выполните: ufw allow ssh"
                sleep 3
                clear
                exit 1
            fi
        fi
        echo -e "  ${GREEN}✓${NC} UFW: ${DIM}${UFW_STATUS:-unknown}${NC}"
    else
        echo -e "  ${DIM}UFW не установлен — используется iptables${NC}"
        if ! dpkg -l | grep -q netfilter-persistent; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
        fi
    fi
}

fix_ipv6_ufw() {
    if ! command -v ip6tables >/dev/null 2>&1; then
        return 0
    fi

    if ! ip6tables -L SCANNERS-BLOCK -n &>/dev/null; then
        return 0
    fi

    if ! ip6tables -L ufw6-before-input -n &>/dev/null; then
        return 0
    fi

    if ip6tables -L ufw6-before-input -n 2>/dev/null | grep -q "SCANNERS-BLOCK"; then
        return 0
    fi

    echo -e "  ${YELLOW}⚠ Обнаружена проблема: SCANNERS-BLOCK (IPv6) не подключена к ufw6-before-input${NC}"
    echo -e "  ${BLUE}▸ Восстановление связи IPv6...${NC}"

    ip6tables -I ufw6-before-input 1 -j SCANNERS-BLOCK 2>/dev/null

    if ip6tables -L ufw6-before-input -n 2>/dev/null | grep -q "SCANNERS-BLOCK"; then
        echo -e "  ${GREEN}✓ Цепочка IPv6 подключена к UFW${NC}"
    else
        echo -e "  ${RED}✗ Не удалось подключить цепочку IPv6${NC}"
        return 1
    fi

    if [[ -f /etc/ufw/before6.rules ]]; then
        if ! grep -q "SCANNERS-BLOCK" /etc/ufw/before6.rules 2>/dev/null; then
            sed -i '/^COMMIT$/i -A ufw6-before-input -j SCANNERS-BLOCK' /etc/ufw/before6.rules
            echo -e "  ${GREEN}✓ Правило добавлено в /etc/ufw/before6.rules${NC}"
        fi
    fi

    return 0
}

check_for_updates() {
    local api_url="https://api.github.com/repos/${TG_REPO}/releases/latest"
    local latest=""

    if command -v curl &> /dev/null; then
        latest=$(curl -fsSL "$api_url" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    elif command -v wget &> /dev/null; then
        latest=$(wget -qO- "$api_url" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    fi

    [[ -z "$latest" ]] && return 1

    latest="${latest#v}"

    if [ "$latest" != "$VERSION" ]; then
        local latest_num version_num
        latest_num=$(echo "$latest" | tr -d '.')
        version_num=$(echo "$VERSION" | tr -d '.')
        if [ "$latest_num" -gt "$version_num" ] 2>/dev/null; then
            echo "$latest"
            return 0
        fi
    fi
    return 1
}

auto_update() {
    local new_version=$1
    clear
    echo -e "${CYAN}${BOLD}  🔄  ДОСТУПНО ОБНОВЛЕНИЕ${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"
    echo -e "  Текущая версия:   ${YELLOW}v${VERSION}${NC}"
    echo -e "  Новая версия:     ${GREEN}v${new_version}${NC}"
    echo ""
    echo -ne "  ${CYAN}👉  Обновить сейчас? (y/N):${NC} "
    trap 'clear; return' INT
    read -r ans < /dev/tty || { clear; return; }
    trap - INT

    if [[ "$ans" != "y" ]]; then
        clear
        return
    fi

    echo -e "\n  ${BLUE}▸ Скачивание новой версии менеджера...${NC}"
    local tmp_manager="/tmp/tguard-manager-new.sh"
    local manager_url="https://raw.githubusercontent.com/${TG_REPO}/main/install-tguard.sh"

    if command -v curl &> /dev/null; then
        curl -fsSL "$manager_url" -o "$tmp_manager" || {
            echo -e "  ${RED}❌ Не удалось скачать${NC}"
            sleep 3
            clear
            return
        }
    elif command -v wget &> /dev/null; then
        wget -qO "$tmp_manager" "$manager_url" || {
            echo -e "  ${RED}❌ Не удалось скачать${NC}"
            sleep 3
            clear
            return
        }
    fi

    echo -e "  ${BLUE}▸ Обновление бинарника до v${new_version}...${NC}"
    local platform
    platform=$(detect_system) || return 1
    local temp_bin="/tmp/tguard-new"
    local bin_url="https://github.com/${TG_REPO}/releases/latest/download/${TG_BINARY}-${platform}"

    if command -v curl &> /dev/null; then
        curl -fsSL "$bin_url" -o "$temp_bin" || {
            echo -e "  ${RED}❌ Не удалось скачать бинарник${NC}"
            sleep 3
            clear
            return
        }
    elif command -v wget &> /dev/null; then
        wget -qO "$temp_bin" "$bin_url" || {
            echo -e "  ${RED}❌ Не удалось скачать бинарник${NC}"
            sleep 3
            clear
            return
        }
    fi

    chmod +x "$temp_bin"

    echo -e "  ${BLUE}▸ Удаление старых версий бинарника...${NC}"
    rm -f /opt/tguard-v* 2>/dev/null

    mv "$temp_bin" "/opt/tguard-v${new_version}"
    ln -sf "/opt/tguard-v${new_version}" "${TG_BIN_PATH}"

    echo -e "  ${BLUE}▸ Обновление менеджера...${NC}"
    bash "$tmp_manager" >/dev/null 2>&1 &
    disown
    rm -f "$tmp_manager"

    echo -e "\n  ${GREEN}✅ Обновление запущено${NC}"
    echo -e "  ${DIM}Менеджер перезапустится через пару секунд${NC}"
    sleep 3
    exit 0
}

cleanup_old_install() {
    echo -e "  ${BLUE}▸ Поиск остатков старой установки...${NC}"

    local FOUND=()

    local BIN_CANDIDATES=(
        "/opt/tguard"
        "/usr/local/bin/tguard-bin"
        "/usr/bin/tguard"
        "/usr/local/sbin/tguard"
        "/bin/tguard"
        "/sbin/tguard"
        "/tmp/tguard"
        "/tmp/tguard-new"
    )
    for f in "${BIN_CANDIDATES[@]}"; do
        if [[ -e "$f" ]]; then
            FOUND+=("$f")
            rm -f "$f"
        fi
    done

    for f in /opt/tguard-v*; do
        if [[ -e "$f" ]]; then
            FOUND+=("$f")
            rm -f "$f"
        fi
    done

    local SCRIPT_CANDIDATES=(
        "/usr/local/bin/antiscan-aggregate-logs.sh"
    )
    for f in "${SCRIPT_CANDIDATES[@]}"; do
        if [[ -e "$f" ]]; then
            FOUND+=("$f")
            rm -f "$f"
        fi
    done

    local UNIT_CANDIDATES=(
        "/etc/systemd/system/antiscan-aggregate.timer"
        "/etc/systemd/system/antiscan-aggregate.service"
        "/lib/systemd/system/antiscan-aggregate.timer"
        "/lib/systemd/system/antiscan-aggregate.service"
    )
    for f in "${UNIT_CANDIDATES[@]}"; do
        if [[ -e "$f" ]]; then
            FOUND+=("$f")
            systemctl stop "$(basename "$f")" 2>/dev/null
            systemctl disable "$(basename "$f")" 2>/dev/null
            rm -f "$f"
        fi
    done
    systemctl daemon-reload 2>/dev/null

    local LOG_CANDIDATES=(
        "/etc/rsyslog.d/10-iptables-scanners.conf"
        "/etc/logrotate.d/iptables-scanners"
    )
    for f in "${LOG_CANDIDATES[@]}"; do
        if [[ -e "$f" ]]; then
            FOUND+=("$f")
            rm -f "$f"
        fi
    done

    if iptables -L SCANNERS-BLOCK -n &>/dev/null; then
        FOUND+=("iptables:SCANNERS-BLOCK")
        iptables -D INPUT -j SCANNERS-BLOCK 2>/dev/null
        iptables -F SCANNERS-BLOCK 2>/dev/null
        iptables -X SCANNERS-BLOCK 2>/dev/null
    fi

    if ipset list SCANNERS-BLOCK-V4 &>/dev/null; then
        FOUND+=("ipset:SCANNERS-BLOCK-V4")
        ipset flush SCANNERS-BLOCK-V4 2>/dev/null
        ipset destroy SCANNERS-BLOCK-V4 2>/dev/null
    fi
    if ipset list SCANNERS-BLOCK-V6 &>/dev/null; then
        FOUND+=("ipset:SCANNERS-BLOCK-V6")
        ipset flush SCANNERS-BLOCK-V6 2>/dev/null
        ipset destroy SCANNERS-BLOCK-V6 2>/dev/null
    fi

    local UFW_CHANGED=false
    if [[ -f /etc/ufw/before.rules ]] && grep -q "SCANNERS-BLOCK" /etc/ufw/before.rules 2>/dev/null; then
        sed -i '/SCANNERS-BLOCK/d' /etc/ufw/before.rules
        UFW_CHANGED=true
        FOUND+=("ufw:before.rules")
    fi
    if [[ -f /etc/ufw/before6.rules ]] && grep -q "SCANNERS-BLOCK" /etc/ufw/before6.rules 2>/dev/null; then
        sed -i '/SCANNERS-BLOCK/d' /etc/ufw/before6.rules
        UFW_CHANGED=true
        FOUND+=("ufw:before6.rules")
    fi
    if [ "$UFW_CHANGED" = true ]; then
        ufw reload 2>/dev/null
    fi

    if [ ${#FOUND[@]} -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} Остатков не найдено — чистая система"
    else
        echo -e "  ${YELLOW}Найдено и удалено ${#FOUND[@]} объектов:${NC}"
        for item in "${FOUND[@]}"; do
            echo -e "    ${DIM}·${NC} $item"
        done
    fi

    systemctl restart rsyslog 2>/dev/null
}

detect_system() {
    local os="" arch=""

    case "$(uname -s)" in
        Linux*) os="linux" ;;
        *)
            echo -e "${RED}❌ Неподдерживаемая ОС: $(uname -s)${NC}"
            return 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        i386|i686)     arch="386" ;;
        armv7l|armv6l) arch="arm" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            echo -e "${RED}❌ Неподдерживаемая архитектура: $(uname -m)${NC}"
            return 1
            ;;
    esac

    echo "${os}-${arch}"
}

get_latest_release_tag() {
    local api_url="https://api.github.com/repos/${TG_REPO}/releases"
    local tag=""

    if [ "$TG_DEV_MODE" = true ]; then
        api_url="${api_url}?per_page=1"
    else
        api_url="${api_url}/latest"
    fi

    if command -v curl &> /dev/null; then
        tag=$(curl -fsSL "${api_url}" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    elif command -v wget &> /dev/null; then
        tag=$(wget -qO- "${api_url}" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    else
        echo -e "${RED}❌ Не найден curl или wget${NC}"
        return 1
    fi

    [[ -z "$tag" ]] && return 1
    echo "$tag"
}

download_binary() {
    local platform=$1
    local temp_file="/tmp/${TG_BINARY}"
    local download_url=""

    if [ "$TG_DEV_MODE" = true ]; then
        local tag
        tag=$(get_latest_release_tag) || return 1
        echo -e "  ${DIM}Найден релиз:${NC} ${YELLOW}${tag}${NC}" >&2
        download_url="https://github.com/${TG_REPO}/releases/download/${tag}/${TG_BINARY}-${platform}"
    else
        download_url="${TG_LATEST_URL}/${TG_BINARY}-${platform}"
    fi

    echo -e "  ${DIM}URL:${NC} ${download_url}" >&2

    if command -v curl &> /dev/null; then
        curl -fsSL "${download_url}" -o "${temp_file}" || return 1
    elif command -v wget &> /dev/null; then
        wget -q "${download_url}" -O "${temp_file}" || return 1
    else
        echo -e "${RED}❌ Не найден curl или wget${NC}"
        return 1
    fi

    echo "${temp_file}"
}

install_binary() {
    local temp_file=$1

    mkdir -p "${TG_INSTALL_DIR}"

    rm -f /opt/tguard-v* 2>/dev/null

    cp "${temp_file}" "${TG_BIN_VERSIONED}"
    chmod +x "${TG_BIN_VERSIONED}"
    rm -f "${temp_file}"

    ln -sf "${TG_BIN_VERSIONED}" "${TG_BIN_PATH}"
}

tg_install() {
    echo -e "  ${BLUE}▸ Определение системы...${NC}"

    local platform
    platform=$(detect_system) || return 1
    echo -e "  ${DIM}Платформа:${NC} ${YELLOW}${platform}${NC}"

    echo -e "  ${BLUE}▸ Скачивание бинарника...${NC}"
    local temp_file
    temp_file=$(download_binary "${platform}") || {
        echo -e "\n  ${RED}❌ Ошибка скачивания бинарника${NC}"
        return 1
    }

    echo -e "  ${BLUE}▸ Установка в ${TG_BIN_VERSIONED}...${NC}"
    install_binary "${temp_file}" || {
        echo -e "\n  ${RED}❌ Ошибка установки${NC}"
        return 1
    }
    echo -e "  ${DIM}Симлинк:${NC} ${TG_BIN_PATH} → ${TG_BIN_VERSIONED}"

    if [[ -x "${TG_BIN_PATH}" ]]; then
        local ver
        ver=$("${TG_BIN_PATH}" --version 2>&1 | head -n1)
        echo -e "  ${GREEN}✅ ${TG_BINARY} v${VERSION} установлен${NC}  ${DIM}${ver}${NC}"
        return 0
    else
        echo -e "\n  ${RED}❌ Проверка установки не удалась${NC}"
        return 1
    fi
}

install_packages() {
    local PKGS=(curl wget rsyslog ipset ufw grep sed coreutils whois)

    echo -e "  ${BLUE}▸ Проверка и установка пакетов...${NC}"
    echo -e "  ${DIM}Список:${NC} ${DIM}${PKGS[*]}${NC}"
    echo ""

    local MISSING=()
    for pkg in "${PKGS[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC}  ${DIM}${pkg}${NC}"
        else
            echo -e "  ${CYAN}↓${NC}  ${pkg}  ${DIM}(будет установлен)${NC}"
            MISSING+=("$pkg")
        fi
    done
    echo ""

    if [ ${#MISSING[@]} -eq 0 ]; then
        echo -e "  ${GREEN}✅ Все пакеты уже установлены${NC}"
    else
        echo -e "  ${DIM}Обновление индексов apt...${NC}"
        apt-get update -q

        echo -e "\n  ${DIM}Установка ${#MISSING[@]} пакет(ов)...${NC}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING[@]}"

        echo -e "\n  ${GREEN}✅ Установлено:${NC} ${MISSING[*]}"
    fi

    systemctl enable --now rsyslog >/dev/null 2>&1
}

uninstall_process() {
    clear
    echo -e "${RED}${BOLD}  🗑️   УДАЛЕНИЕ TGUARD${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"

    if [ "$REMOVE_LOGS" = true ]; then
        echo -e "  ${YELLOW}Будут удалены: бинарники, сервисы, правила, конфиги и логи${NC}"
    else
        echo -e "  ${YELLOW}Будут удалены: бинарники, сервисы, правила, конфиги${NC}"
        echo -e "  ${DIM}Логи останутся в /var/log/${NC}"
    fi
    echo ""

    if [ "$FORCE_YES" != true ]; then
        trap 'clear; return' INT
        read -p "  Продолжить? (y/N): " confirm < /dev/tty || { clear; return; }
        trap - INT

        if [[ "$confirm" != "y" ]]; then
            clear
            return
        fi
    fi

    echo -e "  ${BLUE}▸ Остановка сервисов...${NC}"
    systemctl stop antiscan-aggregate.timer 2>/dev/null
    systemctl stop antiscan-aggregate.service 2>/dev/null
    systemctl disable antiscan-aggregate.timer 2>/dev/null
    systemctl disable antiscan-aggregate.service 2>/dev/null

    if [[ -x "${TG_BIN_PATH}" ]]; then
        echo -e "  ${BLUE}▸ Встроенное удаление tguard...${NC}"
        "${TG_BIN_PATH}" uninstall --yes 2>/dev/null || true
    fi

    echo -e "  ${BLUE}▸ Удаление iptables правил...${NC}"
    while iptables -D INPUT -j SCANNERS-BLOCK 2>/dev/null; do :; done
    iptables -F SCANNERS-BLOCK 2>/dev/null
    iptables -X SCANNERS-BLOCK 2>/dev/null
    while ip6tables -D INPUT -j SCANNERS-BLOCK 2>/dev/null; do :; done
    ip6tables -F SCANNERS-BLOCK 2>/dev/null
    ip6tables -X SCANNERS-BLOCK 2>/dev/null

    echo -e "  ${BLUE}▸ Удаление ipset наборов...${NC}"
    ipset flush SCANNERS-BLOCK-V4 2>/dev/null
    ipset destroy SCANNERS-BLOCK-V4 2>/dev/null
    ipset flush SCANNERS-BLOCK-V6 2>/dev/null
    ipset destroy SCANNERS-BLOCK-V6 2>/dev/null

    echo -e "  ${BLUE}▸ Очистка UFW...${NC}"
    local UFW_CHANGED=false
    for ufw_file in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        if [[ -f "$ufw_file" ]] && grep -q "SCANNERS-BLOCK" "$ufw_file" 2>/dev/null; then
            sed -i '/SCANNERS-BLOCK/d' "$ufw_file"
            UFW_CHANGED=true
        fi
    done
    if [ "$UFW_CHANGED" = true ]; then
        ufw reload 2>/dev/null
    fi

    echo -e "  ${BLUE}▸ Удаление systemd units...${NC}"
    rm -f /etc/systemd/system/antiscan-aggregate.timer
    rm -f /etc/systemd/system/antiscan-aggregate.service
    rm -f /lib/systemd/system/antiscan-aggregate.timer
    rm -f /lib/systemd/system/antiscan-aggregate.service
    systemctl daemon-reload 2>/dev/null
    systemctl reset-failed 2>/dev/null

    echo -e "  ${BLUE}▸ Удаление конфигов rsyslog/logrotate...${NC}"
    rm -f /etc/rsyslog.d/10-iptables-scanners.conf
    rm -f /etc/logrotate.d/iptables-scanners

    echo -e "  ${BLUE}▸ Удаление скриптов и бинарников...${NC}"
    rm -f /usr/local/bin/antiscan-aggregate-logs.sh
    rm -f /usr/local/bin/tguard
    rm -f /usr/local/bin/tguard-bin
    rm -f /usr/bin/tguard
    rm -f /usr/local/sbin/tguard
    rm -f /bin/tguard
    rm -f /sbin/tguard
    rm -f /opt/tguard
    rm -f /opt/tguard-manual.list
    rm -f /tmp/tguard
    rm -f /tmp/tguard-new

    echo -e "  ${BLUE}▸ Удаление всех версий бинарника...${NC}"
    for f in /opt/tguard-v*; do
        if [[ -e "$f" ]]; then
            rm -f "$f"
        fi
    done

    echo -e "  ${BLUE}▸ Удаление файлов ipset persistence...${NC}"
    if [[ -f /etc/ipset.conf ]] && grep -q "SCANNERS-BLOCK" /etc/ipset.conf 2>/dev/null; then
        sed -i '/SCANNERS-BLOCK/d' /etc/ipset.conf
    fi

    echo -e "  ${BLUE}▸ Удаление iptables persistence...${NC}"
    for rules_file in /etc/iptables/rules.v4 /etc/iptables/rules.v6; do
        if [[ -f "$rules_file" ]] && grep -q "SCANNERS-BLOCK" "$rules_file" 2>/dev/null; then
            sed -i '/SCANNERS-BLOCK/d' "$rules_file"
        fi
    done

    if [ "$REMOVE_LOGS" = true ]; then
        echo -e "  ${BLUE}▸ Удаление логов...${NC}"
        rm -f /var/log/iptables-scanners-ipv4.log
        rm -f /var/log/iptables-scanners-ipv6.log
        rm -f /var/log/iptables-scanners-aggregate.csv
        rm -f /var/log/iptables-scanners-ipv4.log.*
        rm -f /var/log/iptables-scanners-ipv6.log.*
        rm -f /var/log/iptables-scanners-aggregate.csv.*
    fi

    echo -e "  ${BLUE}▸ Перезапуск rsyslog...${NC}"
    systemctl restart rsyslog 2>/dev/null

    echo -e "\n  ${GREEN}✅ Всё удалено${NC}"
    sleep 2
    clear

    (sleep 1 && rm -f /opt/tguard-manager.sh) &
    exit 0
}

manage_test_ip() {
    touch "$MANUAL_FILE"

    while true; do
        clear
        echo -e "${MAGENTA}${BOLD}  🧪  УПРАВЛЕНИЕ IP${NC}  ${DIM}· v${VERSION}${NC}"
        echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${RED}1${NC}   ⛔  Забанить IP"
        echo -e "  ${GREEN}2${NC}   ✅  Разбанить IP"
        echo ""
        echo -e "  ${DIM}0${NC}   ↩️   Назад"
        echo ""
        echo -ne "  ${CYAN}👉  Действие:${NC} "

        trap 'clear; return' INT
        read -r action < /dev/tty || { clear; return; }
        trap - INT

        case $action in
            1)
                clear
                echo -e "${MAGENTA}${BOLD}  🧪  УПРАВЛЕНИЕ IP${NC}  ${DIM}· v${VERSION}${NC}"
                echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"
                echo -e "  ${YELLOW}Введите IP для блокировки (Ctrl+C = отмена):${NC}"
                echo -ne "  ${CYAN}IP:${NC} "

                trap 'clear; continue 2' INT
                read -r ip < /dev/tty || { clear; continue; }
                trap - INT

                [[ -z "$ip" ]] && continue

                OUTPUT=$(ipset add SCANNERS-BLOCK-V4 "$ip" 2>&1)
                if [ $? -eq 0 ]; then
                    echo -e "  ${GREEN}✅ IP $ip заблокирован${NC}"
                    if ! grep -Fxq "$ip" "$MANUAL_FILE"; then
                        echo "$ip" >> "$MANUAL_FILE"
                    fi
                else
                    echo -e "  ${RED}❌ Ошибка:${NC} $OUTPUT"
                fi
                read -p "  [Enter]..." < /dev/tty
                ;;
            2)
                clear
                echo -e "${MAGENTA}${BOLD}  🧪  УПРАВЛЕНИЕ IP${NC}  ${DIM}· v${VERSION}${NC}"
                echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
                echo -e "\n  ${GREEN}${BOLD}Список ручных банов${NC}"
                echo -e "${DIM}  ──────────────────────────────────────────────${NC}"

                if [ ! -s "$MANUAL_FILE" ]; then
                    echo -e "  ${DIM}Список пуст${NC}"
                    read -p "  [Enter]..." < /dev/tty
                    continue
                fi

                mapfile -t MANUAL_IPS < "$MANUAL_FILE"
                i=1
                for ip in "${MANUAL_IPS[@]}"; do
                    printf "  ${CYAN}%2d)${NC}  %s\n" "$i" "$ip"
                    ((i++))
                done

                echo ""
                echo -e "  ${YELLOW}Введите номер из списка или IP вручную:${NC}"
                echo -ne "  ${CYAN}Выбор:${NC} "

                trap 'clear; continue 2' INT
                read -r input < /dev/tty || { clear; continue; }
                trap - INT

                [[ -z "$input" ]] && continue

                TARGET_IP=""
                if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -le "${#MANUAL_IPS[@]}" ] && [ "$input" -gt 0 ]; then
                    TARGET_IP="${MANUAL_IPS[$((input-1))]}"
                else
                    TARGET_IP="$input"
                fi

                echo -e "  ${DIM}Разбаниваем:${NC} ${YELLOW}$TARGET_IP${NC}"

                OUTPUT=$(ipset del SCANNERS-BLOCK-V4 "$TARGET_IP" 2>&1)
                sed -i "/^$TARGET_IP$/d" "$MANUAL_FILE"

                if [ $? -eq 0 ]; then
                    echo -e "  ${GREEN}✅ Разбанен${NC}"
                else
                    echo -e "  ${RED}⚠️  $OUTPUT${NC} (удалён из списка)"
                fi
                read -p "  [Enter]..." < /dev/tty
                ;;
            0)
                clear
                return
                ;;
        esac
    done
}

update_lists() {
    clear
    echo -e "${CYAN}${BOLD}  🔄  ОБНОВЛЕНИЕ СПИСКОВ${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"

    local FAIL=0
    for url in "$LIST_ANTISCAN" "$LIST_GOV" "$LIST_MISC"; do
        printf "  ${DIM}·${NC} %s\n" "$url"
        if curl -fsI "$url" >/dev/null 2>&1; then
            echo -e "    ${GREEN}✓ доступен${NC}"
        else
            echo -e "    ${RED}✗ недоступен${NC}"
            FAIL=1
        fi
    done

    if [ $FAIL -ne 0 ]; then
        echo -e "\n  ${RED}❌ Часть списков недоступна${NC}"
        read -p "  [Enter]..." < /dev/tty
        clear
        return 1
    fi

    echo -e "\n  ${BLUE}▸ Применение...${NC}"
    "${TG_BIN_PATH}" full -u "$LIST_ANTISCAN" -u "$LIST_GOV" -u "$LIST_MISC" --enable-logging

    echo ""
    fix_ipv6_ufw

    echo -e "\n  ${GREEN}✅ Готово${NC}"
    sleep 2
    clear
}

install_process() {
    clear
    echo -e "${CYAN}${BOLD}  🚀  УСТАНОВКА TGUARD${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"

    cleanup_old_install

    echo ""
    check_firewall_safety

    echo ""
    install_packages

    echo -e "\n  ${BLUE}▸ Установка tguard...${NC}"
    if ! tg_install; then
        echo -e "\n  ${RED}❌ ОШИБКА УСТАНОВКИ!${NC}"
        sleep 3
        clear
        exit 1
    fi

    echo -e "\n  ${BLUE}▸ Настройка правил...${NC}"
    if ! "${TG_BIN_PATH}" full -u "$LIST_ANTISCAN" -u "$LIST_GOV" -u "$LIST_MISC" --enable-logging; then
        echo -e "\n  ${YELLOW}⚠️  Не удалось применить списки${NC}"
        echo -e "  ${DIM}Попробуй позже: tguard update${NC}"
        sleep 3
    fi

    echo ""
    fix_ipv6_ufw

    mkdir -p /var/log
    touch /var/log/iptables-scanners-{ipv4,ipv6}.log
    LOG_GROUP="syslog"
    getent group adm >/dev/null && LOG_GROUP="adm"
    chown syslog:$LOG_GROUP /var/log/iptables-scanners-*.log
    chmod 640 /var/log/iptables-scanners-*.log

    touch "$MANUAL_FILE"

    systemctl restart rsyslog >/dev/null 2>&1
    systemctl restart antiscan-aggregate.service 2>/dev/null || true
    systemctl restart antiscan-aggregate.timer >/dev/null 2>&1

    echo -e "\n  ${GREEN}✅ Установка завершена${NC}"
    sleep 2
    clear
}

view_log() {
    local file=$1
    clear
    echo -e "${YELLOW}${BOLD}  🕵   LIVE LOG${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
    echo -e "  ${DIM}Ctrl+C — назад в меню${NC}\n"

    trap 'clear; return' INT
    tail -f "$file"
    trap - INT
    clear
}

show_help() {
    clear
    echo -e "${CYAN}${BOLD}  🛡️   TGUARD${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${BOLD}Использование:${NC}  tguard [команда] [опции]"
    echo ""
    echo -e "  ${BOLD}Команды:${NC}"
    echo -e "    ${GREEN}install${NC}         Установить TGuard"
    echo -e "    ${GREEN}monitor${NC}         Открыть меню управления ${DIM}(по умолчанию)${NC}"
    echo -e "    ${GREEN}update${NC}          Обновить списки блокировок"
    echo -e "    ${GREEN}upgrade${NC}         Проверить и установить новую версию"
    echo -e "    ${GREEN}fix-ipv6${NC}        Починить связь SCANNERS-BLOCK ↔ UFW IPv6"
    echo -e "    ${RED}uninstall${NC}       Удалить TGuard и все его файлы"
    echo -e "    ${DIM}-v, --version${NC}   Показать версию"
    echo -e "    ${DIM}-h, --help${NC}      Показать эту справку"
    echo ""
    echo -e "  ${BOLD}Опции uninstall:${NC}"
    echo -e "    ${CYAN}--remove-logs${NC}, ${CYAN}-r${NC}   Удалить логи из /var/log"
    echo -e "    ${CYAN}--yes${NC}, ${CYAN}-y${NC}           Без подтверждения"
    echo ""
    echo -e "  ${BOLD}Примеры:${NC}"
    echo -e "    ${DIM}tguard upgrade${NC}                       ${DIM}# проверить обновление${NC}"
    echo -e "    ${DIM}tguard fix-ipv6${NC}                      ${DIM}# починить IPv6 связь${NC}"
    echo -e "    ${DIM}tguard uninstall --yes --remove-logs${NC} ${DIM}# полная очистка${NC}"
    echo ""
    exit 0
}

show_version() {
    clear
    echo -e "${CYAN}${BOLD}  🛡️   TGUARD${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${BOLD}TGuard Manager${NC}  ${DIM}версия${NC} ${MAGENTA}${BOLD}v${VERSION}${NC}"
    echo -e "  ${DIM}Firewall manager для защиты от сканеров и атак${NC}"
    echo ""

    local bin_ver=""
    if [[ -x "${TG_BIN_PATH}" ]]; then
        bin_ver=$("${TG_BIN_PATH}" --version 2>&1 | head -n1)
        echo -e "  ${DIM}Бинарник:${NC} ${bin_ver}"
    fi

    echo ""
    local new_ver
    if new_ver=$(check_for_updates); then
        echo -e "  ${YELLOW}⬆ Доступна новая версия: v${new_ver}${NC}"
        echo -e "  ${DIM}Обновить: tguard upgrade${NC}"
    else
        echo -e "  ${GREEN}✓ Установлена последняя версия${NC}"
    fi
    echo ""
    exit 0
}

upgrade_process() {
    local new_ver
    if new_ver=$(check_for_updates); then
        auto_update "$new_ver"
    else
        clear
        echo -e "${CYAN}${BOLD}  🛡️   TGUARD${NC}  ${DIM}· v${VERSION}${NC}"
        echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${GREEN}✓ Установлена последняя версия (v${VERSION})${NC}"
        echo ""
        sleep 2
    fi
}

fix_ipv6_process() {
    clear
    echo -e "${CYAN}${BOLD}  🔧  ПОЧИНКА IPv6${NC}  ${DIM}· v${VERSION}${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"

    if ! command -v ip6tables >/dev/null 2>&1; then
        echo -e "  ${DIM}ip6tables не установлен — IPv6 не используется${NC}"
        sleep 2
        clear
        return
    fi

    if ! ip6tables -L SCANNERS-BLOCK -n &>/dev/null; then
        echo -e "  ${YELLOW}⚠ Цепочка SCANNERS-BLOCK (IPv6) не создана${NC}"
        echo -e "  ${DIM}Сначала запусти: tguard install${NC}"
        sleep 3
        clear
        return
    fi

    echo -e "  ${BLUE}▸ Проверка связи SCANNERS-BLOCK ↔ ufw6-before-input...${NC}"

    if ip6tables -L ufw6-before-input -n 2>/dev/null | grep -q "SCANNERS-BLOCK"; then
        echo -e "  ${GREEN}✓ Связь уже установлена${NC}"
        sleep 2
        clear
        return
    fi

    fix_ipv6_ufw

    echo ""
    echo -e "  ${GREEN}✅ Готово${NC}"
    sleep 2
    clear
}

show_menu() {
    local new_ver
    if new_ver=$(check_for_updates); then
        auto_update "$new_ver"
    fi

    while true; do
        clear

        IPSET_CNT=$(ipset list SCANNERS-BLOCK-V4 2>/dev/null | grep "Number of entries" | awk '{print $4}')
        [[ -z "$IPSET_CNT" ]] && IPSET_CNT="0"
        PKTS_CNT=$(iptables -vnL SCANNERS-BLOCK 2>/dev/null | grep "LOG" | awk '{print $1}')
        [[ -z "$PKTS_CNT" ]] && PKTS_CNT="0"

        echo ""
        echo -e "  ${CYAN}${BOLD}🛡️   TGUARD${NC}  ${DIM}· v${VERSION}${NC}"
        echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
        printf "  ${DIM}📊${NC}  Подсетей      ${GREEN}${BOLD}%8s${NC}\n" "$IPSET_CNT"
        printf "  ${DIM}🔥${NC}  Атак отбито   ${RED}${BOLD}%8s${NC}\n" "$PKTS_CNT"
        echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
        echo ""

        echo -e "  ${GREEN}1${NC}   📈  Топ атак            ${DIM}CSV${NC}"
        echo -e "  ${GREEN}2${NC}   🕵   Логи IPv4           ${DIM}live${NC}"
        echo -e "  ${GREEN}3${NC}   🕵   Логи IPv6           ${DIM}live${NC}"
        echo -e "  ${GREEN}4${NC}   🧪  Управление IP        ${DIM}ban / unban${NC}"
        echo -e "  ${GREEN}5${NC}   🔄  Обновить списки     ${DIM}update${NC}"
        echo -e "  ${GREEN}6${NC}   🛠️   Переустановить      ${DIM}reinstall${NC}"
        echo -e "  ${GREEN}8${NC}   ⬆️   Обновить версию    ${DIM}upgrade${NC}"
        echo -e "  ${GREEN}9${NC}   🔧  Починить IPv6      ${DIM}fix-ipv6${NC}"
        echo -e "  ${RED}7${NC}   🗑️   Удалить всё         ${DIM}uninstall${NC}"
        echo ""
        echo -e "  ${DIM}0${NC}   ❌  Выход"
        echo ""

        echo -ne "  ${CYAN}👉  Ваш выбор:${NC} "

        trap 'clear; exit 0' INT
        read -r choice < /dev/tty || { clear; exit 0; }
        trap - INT

        case $choice in
            1)
                clear
                echo -e "${GREEN}${BOLD}  📈  ТОП 20${NC}  ${DIM}· v${VERSION}${NC}"
                echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"
                [ -f /var/log/iptables-scanners-aggregate.csv ] && \
                    tail -20 /var/log/iptables-scanners-aggregate.csv || \
                    echo -e "  ${DIM}Нет данных${NC}"
                read -p $'\n  [Enter] назад...' < /dev/tty
                ;;
            2) view_log "/var/log/iptables-scanners-ipv4.log" ;;
            3) view_log "/var/log/iptables-scanners-ipv6.log" ;;
            4) manage_test_ip ;;
            5) update_lists ;;
            6)
                rm -f /var/log/iptables-scanners-aggregate.csv
                install_process
                ;;
            7)
                REMOVE_LOGS=true
                FORCE_YES=false
                uninstall_process
                ;;
            8) upgrade_process ;;
            9) fix_ipv6_process ;;
            0)
                clear
                exit 0
                ;;
            *) echo -e "  ${RED}Неверно${NC}"; sleep 1 ;;
        esac
    done
}

check_root

REMOVE_LOGS=false
FORCE_YES=false

case "${1:-}" in
    install)      install_process ;;
    monitor)      show_menu ;;
    update)       update_lists ;;
    upgrade)      upgrade_process ;;
    fix-ipv6)     fix_ipv6_process ;;
    uninstall)
        shift
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --remove-logs|-r) REMOVE_LOGS=true ;;
                --yes|-y)         FORCE_YES=true ;;
            esac
            shift
        done
        uninstall_process
        ;;
    -v|--version) show_version ;;
    -h|--help)    show_help ;;
    *)            show_menu ;;
esac
EOF

chmod +x "$MANAGER_PATH"
ln -sf "$MANAGER_PATH" "$LINK_PATH"

if [[ ! -x /opt/tguard ]]; then
    /opt/tguard-manager.sh install
fi

/opt/tguard-manager.sh monitor