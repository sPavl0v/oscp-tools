#!/usr/bin/env bash

# =========================
# Linux Low-Priv / Root File-Cred Hunting
# Single-file output version
# Focus: configs, artifacts, plaintext creds, passwords, connect strings
# Tuned to avoid noisy CMS/framework/template junk
# =========================

set +e
export LC_ALL=C

OUTFILE="${1:-./enum_report.txt}"
DEEP=0

if [[ "$1" == "--deep" || "$2" == "--deep" || "$3" == "--deep" ]]; then
    DEEP=1
fi

# ---------- Setup ----------
OUTDIR="$(dirname "$OUTFILE")"
mkdir -p "$OUTDIR" 2>/dev/null
: > "$OUTFILE"

# ---------- Helpers ----------
write_section() {
    printf "\n========== %s ==========\n" "$1" | tee -a "$OUTFILE"
}

write_info() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

is_root() {
    [[ "$(id -u 2>/dev/null)" == "0" ]]
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

safe_head() {
    local file="$1"
    local lines="${2:-80}"
    if [[ -r "$file" ]]; then
        head -n "$lines" "$file" 2>/dev/null
    fi
}

get_match_snippet() {
    local line="$1"
    line="$(printf "%s" "$line" | tr '\t' ' ' | tr '\r' ' ' | tr '\n' ' ')"
    printf "%s" "$line" | cut -c1-220
}

file_size_bytes() {
    local f="$1"
    if have_cmd stat; then
        stat -c %s "$f" 2>/dev/null || wc -c < "$f" 2>/dev/null
    else
        wc -c < "$f" 2>/dev/null
    fi
}

mtime_string() {
    local f="$1"
    if have_cmd stat; then
        stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1
    else
        ls -ld --time-style=long-iso "$f" 2>/dev/null | awk '{print $6" "$7}'
    fi
}

# ---------- Exclusions ----------
SCRIPT_EXCLUDE_NAMES=(
    "enum-linux-creds.sh"
    "enum_report.txt"
)

EXCLUDED_EXTENSIONS=(
    "so" "a" "o" "pyc" "pyo" "class" "jar" "war" "ear"
    "jpg" "jpeg" "png" "gif" "bmp" "ico" "webp" "mp3" "mp4" "avi" "mkv" "mov"
    "gz" "xz" "bz2" "lz4" "zst" "tar" "deb" "rpm" "iso"
    "ttf" "otf" "woff" "woff2"
    "swp" "cache" "pack" "idx" "lock" "journal"
    "sqlite-wal" "sqlite-shm"
    "map"
)

EXCLUDED_PATH_PREFIXES=(
    "/proc"
    "/sys"
    "/dev"
    "/run"
    "/snap"
    "/tmp/.mount_"
    "/var/lib/docker"
    "/var/lib/containerd"
    "/var/lib/kubelet"
    "/var/lib/snapd"
    "/var/cache"
    "/usr/share"
    "/usr/src"
    "/lib/modules"
)

EXCLUDED_PATH_CONTAINS=(
    "/node_modules/"
    "/.cache/"
    "/vendor/bundle/"
    "/site-packages/"
    "/dist-packages/"
    "/__pycache__/"
    "/.npm/"
    "/.cargo/registry/"
    "/.rustup/"
    "/go/pkg/"
    "/.local/share/Trash/"
    "/.mozilla/firefox/"
    "/.config/google-chrome/"
    "/.cache/google-chrome/"
    "/.config/chromium/"
    "/.cache/chromium/"
    "/man/"
    "/locale/"
    "/language/"
    "/languages/"
    "/help/"
    "/doc/"
    "/docs/"
    "/examples/"
    "/terminfo/"
    "/icons/"
    "/themes/"
    "/fonts/"
    "/journal/"
    "/logs/"
    "/log/"
    "/media/vendor/"
    "/media/system/js/"
    "/vendor/jquery/"
    "/vendor/bootstrap/"
    "/vendor/tinymce/"
    "/vendor/ckeditor/"
    "/vendor/select2/"
    "/vendor/fontawesome/"
    "/vendor/mediaelement/"
    "/vendor/hotkeysjs/"
    "/tmpl/"
    "/templates/"
    "/views/"
    "/layouts/"
    "/cache/"
    "/components/"
    "/modules/"
    "/plugins/"
    "/administrator/modules/"
)

TEXT_EXTENSIONS=(
    "txt" "conf" "cfg" "cnf" "config" "ini" "json" "yaml" "yml" "xml"
    "properties" "props" "env" "php" "asp" "aspx" "jsp" "js" "ts"
    "py" "rb" "pl" "sh" "bash" "zsh" "ksh" "csh"
    "sql" "csv" "log"
    "md" "rst"
    "service"
)

KNOWN_HIGH_VALUE_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/sudoers.d"
    "/etc/fstab"
    "/etc/exports"
    "/etc/crontab"
    "/etc/anacrontab"
    "/etc/environment"
    "/etc/profile"
    "/etc/bash.bashrc"
    "/etc/hosts"
    "/etc/resolv.conf"
    "/etc/ssh/sshd_config"
    "/etc/ssh/ssh_config"
    "/etc/mysql/my.cnf"
    "/etc/my.cnf"
    "/etc/postgresql"
    "/etc/nginx"
    "/etc/apache2"
    "/etc/httpd"
    "/var/www"
    "/srv"
    "/opt"
)

is_excluded_filename() {
    local name="$1"
    local x
    for x in "${SCRIPT_EXCLUDE_NAMES[@]}"; do
        [[ "$name" == "$x" ]] && return 0
    done
    return 1
}

is_excluded_extension() {
    local ext="${1#.}"
    ext="$(printf "%s" "$ext" | tr '[:upper:]' '[:lower:]')"
    local x
    for x in "${EXCLUDED_EXTENSIONS[@]}"; do
        [[ "$ext" == "$x" ]] && return 0
    done
    return 1
}

is_excluded_path() {
    local p="$1"
    local x
    for x in "${EXCLUDED_PATH_PREFIXES[@]}"; do
        [[ "$p" == "$x" || "$p" == "$x/"* ]] && return 0
    done
    return 1
}

is_excluded_path_contains() {
    local p="$1"
    local p_lc
    p_lc="$(printf "%s" "$p" | tr '[:upper:]' '[:lower:]')"
    local x
    for x in "${EXCLUDED_PATH_CONTAINS[@]}"; do
        [[ "$p_lc" == *"$x"* ]] && return 0
    done
    [[ "$p_lc" == *"/language/"* || "$p_lc" == *"/languages/"* || "$p_lc" == *"language"* ]] && return 0
    return 1
}

looks_like_binary() {
    local f="$1"
    file -b "$f" 2>/dev/null | grep -Eqi 'executable|shared object|ELF|archive|image|audio|video|font|compressed|data'
}

is_text_candidate() {
    local f="$1"
    local ext="${f##*.}"
    ext="$(printf "%s" "$ext" | tr '[:upper:]' '[:lower:]')"
    local x
    for x in "${TEXT_EXTENSIONS[@]}"; do
        [[ "$ext" == "$x" ]] && return 0
    done

    if have_cmd file; then
        file -b "$f" 2>/dev/null | grep -Eqi 'text|ascii|unicode|utf-8|xml|json|script'
        return $?
    fi
    return 1
}

can_read_dir() {
    [[ -d "$1" && -r "$1" && -x "$1" ]]
}

# Only actual high-signal filename hits for OSCP.
# No generic password.php, config.php, settings.py, passwd-like names, etc.
is_high_signal_filename_hit() {
    local path="$1"
    local bname
    bname="$(basename "$path")"

    printf "%s\n" "$bname" | grep -Eqi \
        '(^id_rsa$|^id_dsa$|^id_ecdsa$|^id_ed25519$|^authorized_keys$|^known_hosts$|\.pem$|\.key$|\.p12$|\.pfx$|\.ppk$|\.kdbx$|\.ovpn$|^\.env(\..+)?$|^\.pgpass$|^\.netrc$|^\.git-credentials$|^\.dockercfg$|secret|cred|creds|backup|backups|\.bak$|\.old$)'
}

# Positive patterns: actual values, auth material, connection strings, private keys
CONTENT_REGEX='password[[:space:]]*[:=][[:space:]]*[^[:space:]]+|passwd[[:space:]]*[:=][[:space:]]*[^[:space:]]+|pwd[[:space:]]*[:=][[:space:]]*[^[:space:]]+|pass[[:space:]]*[:=][[:space:]]*[^[:space:]]+|db_pass(word)?[[:space:]]*[:=][[:space:]]*[^[:space:]]+|mysql_pwd[[:space:]]*[:=][[:space:]]*[^[:space:]]+|pgpassword[[:space:]]*[:=][[:space:]]*[^[:space:]]+|bindpw[[:space:]]*[:=][[:space:]]*[^[:space:]]+|authorization[[:space:]]*:[[:space:]]*basic[[:space:]]+[A-Za-z0-9+/=:_-]+|connectionstring[[:space:]]*[:=][[:space:]]*.+|connstr[[:space:]]*[:=][[:space:]]*.+|jdbc:[^"'"'"'[:space:]]+|mongodb(\+srv)?://[^"'"'"'[:space:]]+|postgres(ql)?://[^"'"'"'[:space:]]+|mysql://[^"'"'"'[:space:]]+|redis://[^"'"'"'[:space:]]+|amqp://[^"'"'"'[:space:]]+|ftp://[^"'"'"'[:space:]]+|s3://[^"'"'"'[:space:]]+|BEGIN[[:space:]]+(RSA|OPENSSH|EC|DSA)[[:space:]]+PRIVATE[[:space:]]+KEY'

is_junk_match_line() {
    local path="$1"
    local line="$2"
    local p_lc l_lc

    p_lc="$(printf "%s" "$path" | tr '[:upper:]' '[:lower:]')"
    l_lc="$(printf "%s" "$line" | tr '[:upper:]' '[:lower:]')"

    if [[ "$p_lc" == *"/language/"* || "$p_lc" == *"/languages/"* || "$p_lc" == *"/media/system/js/"* || "$p_lc" == *"/media/vendor/"* || "$p_lc" == *"/tmpl/"* || "$p_lc" == *"/templates/"* || "$p_lc" == *"/views/"* || "$p_lc" == *"/layouts/"* || "$p_lc" == *"/modules/"* || "$p_lc" == *"/components/"* || "$p_lc" == *"/plugins/"* ]]; then
        return 0
    fi

    if printf "%s" "$l_lc" | grep -Eqi \
        'password reset|reset request|confirm the password|complete the password|submit the password|request a password|unset\(.*password|password1|password2|type=.password|name=.password|placeholder=.password|label.*password|method to .*password|comment.*password|forgot password|resetcontroller|remindcontroller|profilecontroller|must login to edit the password|fields/password|passwordview|passwordstrength'; then
        return 0
    fi

    if printf "%s" "$l_lc" | grep -Eqi '^[[:space:]]*(//|/\*|\*|#)' &&
       ! printf "%s" "$l_lc" | grep -Eqi 'password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|pwd[[:space:]]*[:=]|bindpw[[:space:]]*[:=]|pgpassword[[:space:]]*[:=]|mysql_pwd[[:space:]]*[:=]|authorization[[:space:]]*:[[:space:]]*basic|jdbc:|mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://|amqp://|ftp://|s3://|private key'; then
        return 0
    fi

    return 1
}

# ---------- Header ----------
IS_ROOT="false"
is_root && IS_ROOT="true"

write_section "Run Info"
write_info "Date: $(date)"
write_info "Output file: $OUTFILE"
write_info "Deep mode: $DEEP"
write_info "Is root: $IS_ROOT"

# ---------- Baseline ----------
write_section "Host / User Baseline"
{
    echo "Date: $(date)"
    echo "Hostname: $(hostname 2>/dev/null)"
    echo "Kernel: $(uname -a 2>/dev/null)"
    echo "User: $(id 2>/dev/null)"
    echo "Whoami: $(whoami 2>/dev/null)"
    echo "PWD: $(pwd 2>/dev/null)"
    echo "Shell: ${SHELL:-}"
    echo "Home: ${HOME:-}"
    echo
    echo "Environment Variables:"
    env 2>/dev/null | sort
} | tee -a "$OUTFILE"

# ---------- High-yield direct artifact checks ----------
write_section "App-Specific High-Yield Checks"

APP_FILES=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.ash_history"
    "$HOME/.mysql_history"
    "$HOME/.psql_history"
    "$HOME/.sqlite_history"
    "$HOME/.lesshst"
    "$HOME/.wget-hsts"
    "$HOME/.netrc"
    "$HOME/.git-credentials"
    "$HOME/.gitconfig"
    "$HOME/.npmrc"
    "$HOME/.pypirc"
    "$HOME/.docker/config.json"
    "$HOME/.dockercfg"
    "$HOME/.kube/config"
    "$HOME/.aws/credentials"
    "$HOME/.aws/config"
    "$HOME/.azure/accessTokens.json"
    "$HOME/.config/gcloud/credentials.db"
    "$HOME/.config/gcloud/application_default_credentials.json"
    "$HOME/.pgpass"
    "$HOME/.ssh/config"
    "$HOME/.ssh/authorized_keys"
    "$HOME/.ssh/known_hosts"
    "$HOME/.s3cfg"
    "$HOME/.ftpconfig"
    "$HOME/.viminfo"
)

APP_DIRS=(
    "$HOME/.ssh"
    "$HOME/.aws"
    "$HOME/.azure"
    "$HOME/.config/gcloud"
    "$HOME/.kube"
    "$HOME/.docker"
)

for f in "${APP_FILES[@]}"; do
    if [[ -e "$f" ]]; then
        write_info ""
        write_info "[FILE] $f"
        safe_head "$f" 80 | tee -a "$OUTFILE"
    fi
done

for d in "${APP_DIRS[@]}"; do
    if can_read_dir "$d"; then
        write_info ""
        write_info "[DIR] $d"
        find "$d" -maxdepth 2 -type f 2>/dev/null | sed 's/^/  /' | head -n 200 | tee -a "$OUTFILE"
    fi
done

# ---------- Other-user profile probing ----------
write_section "Readable Other-User Home Probing"

if [[ -d /home ]]; then
    CURRENT_HOME_REAL="$(readlink -f "$HOME" 2>/dev/null)"
    find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while read -r uhome; do
        UHOME_REAL="$(readlink -f "$uhome" 2>/dev/null)"
        [[ "$UHOME_REAL" == "$CURRENT_HOME_REAL" ]] && continue

        for p in "$uhome" "$uhome/.ssh" "$uhome/.aws" "$uhome/.config" "$uhome/Desktop" "$uhome/Documents" "$uhome/Downloads"; do
            if can_read_dir "$p"; then
                write_info "[Readable] $p"
            else
                [[ -e "$p" ]] && write_info "[Denied/Unreadable] $p"
            fi
        done
    done
fi

# ---------- High-yield base paths ----------
write_section "High-Yield Directory Targets"

TARGET_PATHS=(
    "$HOME"
    "/home"
    "/root"
    "/etc"
    "/opt"
    "/srv"
    "/var/www"
    "/var/backups"
    "/backup"
    "/backups"
    "/mnt"
    "/media"
    "/usr/local"
)

if [[ "$DEEP" -eq 1 ]]; then
    TARGET_PATHS+=("/var" "/")
fi

TARGET_PATHS_UNIQ=()
for p in "${TARGET_PATHS[@]}"; do
    skip=0
    for x in "${TARGET_PATHS_UNIQ[@]}"; do
        [[ "$x" == "$p" ]] && skip=1 && break
    done
    [[ "$skip" -eq 0 ]] && TARGET_PATHS_UNIQ+=("$p")
done

for tp in "${TARGET_PATHS_UNIQ[@]}"; do
    if [[ -e "$tp" ]]; then
        if is_excluded_path "$tp" || is_excluded_path_contains "$tp"; then
            write_info "[-] Excluded: $tp"
        else
            write_info "[+] Exists: $tp"
        fi
    fi
done

# ---------- Suspicious filename search ----------
write_section "Suspicious Filename Search"

DIR_REGEX='(^|/)(backup|backups|bak|old|archive|deprecated|legacy)($|/)'
MAXDEPTH_FIND=8
[[ "$DEEP" -eq 1 ]] && MAXDEPTH_FIND=14

for base in "${TARGET_PATHS_UNIQ[@]}"; do
    [[ ! -e "$base" ]] && continue
    if is_excluded_path "$base" || is_excluded_path_contains "$base"; then
        write_info ""
        write_info "--- Skipping excluded base path: $base ---"
        continue
    fi

    write_info ""
    write_info "--- Searching filenames in: $base ---"

    find "$base" -xdev -maxdepth "$MAXDEPTH_FIND" \( -type f -o -type l \) 2>/dev/null | while read -r f; do
        [[ ! -e "$f" ]] && continue
        is_excluded_path "$f" && continue
        is_excluded_path_contains "$f" && continue

        bname="$(basename "$f")"
        is_excluded_filename "$bname" && continue

        ext="${f##*.}"
        is_excluded_extension "$ext" && continue

        if is_high_signal_filename_hit "$f" || printf "%s" "$f" | grep -Eqi "$DIR_REGEX"; then
            write_info "$(mtime_string "$f")	$(file_size_bytes "$f")	$f"
        fi
    done
done

# ---------- Suspicious directory search ----------
write_section "Suspicious Directory Search"

for base in "${TARGET_PATHS_UNIQ[@]}"; do
    [[ ! -d "$base" ]] && continue
    is_excluded_path "$base" && continue
    is_excluded_path_contains "$base" && continue

    find "$base" -xdev -maxdepth "$MAXDEPTH_FIND" -type d 2>/dev/null | while read -r d; do
        is_excluded_path "$d" && continue
        is_excluded_path_contains "$d" && continue

        if printf "%s" "$d" | grep -Eqi "$DIR_REGEX"; then
            write_info "[Dir] $d"
        fi
    done
done

# ---------- Direct known file checks ----------
write_section "Direct Known File Checks"

for k in "${KNOWN_HIGH_VALUE_FILES[@]}"; do
    if [[ -e "$k" ]]; then
        write_info "[+] Found: $k"

        if [[ -f "$k" && -r "$k" ]]; then
            safe_head "$k" 120 | tee -a "$OUTFILE"
        elif [[ -d "$k" && -r "$k" ]]; then
            find "$k" -maxdepth 2 2>/dev/null | head -n 100 | tee -a "$OUTFILE"
        fi
    fi
done

# ---------- Shell history review ----------
write_section "Shell History"

HIST_FILES=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.ash_history"
    "$HOME/.mysql_history"
    "$HOME/.psql_history"
    "$HOME/.sqlite_history"
)

HIST_PATTERNS='password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|pwd[[:space:]]*[:=]|mysql[[:space:]]+-u|psql|mongo|redis-cli|aws[[:space:]]|kubectl|docker[[:space:]]+login|git[[:space:]]+clone[[:space:]]+https://|scp[[:space:]]|smbclient|mount[[:space:]].*username=|export[[:space:]].*(PASS|KEY|MYSQL_PWD|PGPASSWORD)|MYSQL_PWD|PGPASSWORD|sshpass|bindpw[[:space:]]*='

for hf in "${HIST_FILES[@]}"; do
    if [[ -r "$hf" ]]; then
        write_info "[History] $hf"
        grep -Ein "$HIST_PATTERNS" "$hf" 2>/dev/null | while IFS=: read -r ln rest; do
            is_junk_match_line "$hf" "$rest" && continue
            write_info "Line $ln: $(get_match_snippet "$rest")"
        done
    fi
done

if is_root; then
    write_section "Root-Only Additional User Histories"

    find /home /root -maxdepth 2 -type f \( -name ".bash_history" -o -name ".zsh_history" -o -name ".mysql_history" -o -name ".psql_history" \) 2>/dev/null | while read -r hf; do
        [[ ! -r "$hf" ]] && continue
        write_info "[History] $hf"
        grep -Ein "$HIST_PATTERNS" "$hf" 2>/dev/null | while IFS=: read -r ln rest; do
            is_junk_match_line "$hf" "$rest" && continue
            write_info "Line $ln: $(get_match_snippet "$rest")"
        done
    done
fi

# ---------- SSH / key material ----------
write_section "SSH / Key Material"

for base in "$HOME/.ssh" /root/.ssh /etc/ssh /home; do
    [[ ! -e "$base" ]] && continue
    write_info ""
    write_info "--- SSH scan in: $base ---"

    find "$base" -maxdepth 4 2>/dev/null | while read -r f; do
        [[ ! -e "$f" ]] && continue
        is_excluded_path "$f" && continue
        is_excluded_path_contains "$f" && continue

        bname="$(basename "$f")"
        if printf "%s" "$bname" | grep -Eqi '(^id_rsa$|^id_dsa$|^id_ecdsa$|^id_ed25519$|authorized_keys|known_hosts|config|\.pem$|\.key$|\.pub$|\.ppk$)'; then
            write_info "$f"
            [[ -f "$f" && -r "$f" ]] && safe_head "$f" 40 | tee -a "$OUTFILE"
        fi
    done
done

# ---------- Content search ----------
write_section "Content Search in Likely Text/Config Files"

MAX_FILE_SIZE=$((5 * 1024 * 1024))
[[ "$DEEP" -eq 1 ]] && MAX_FILE_SIZE=$((15 * 1024 * 1024))

for base in "${TARGET_PATHS_UNIQ[@]}"; do
    [[ ! -e "$base" ]] && continue
    if is_excluded_path "$base" || is_excluded_path_contains "$base"; then
        write_info ""
        write_info "--- Skipping excluded content-search base path: $base ---"
        continue
    fi

    write_info ""
    write_info "--- Content search in: $base ---"

    while IFS= read -r f; do
        [[ ! -r "$f" ]] && continue
        is_excluded_path "$f" && continue
        is_excluded_path_contains "$f" && continue

        bname="$(basename "$f")"
        is_excluded_filename "$bname" && continue

        ext="${f##*.}"
        is_excluded_extension "$ext" && continue

        size="$(file_size_bytes "$f")"
        [[ -z "$size" ]] && continue
        [[ "$size" -gt "$MAX_FILE_SIZE" ]] && continue

        is_text_candidate "$f" || continue
        if have_cmd file && looks_like_binary "$f"; then
            continue
        fi

        matches=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ln="${line%%:*}"
            rest="${line#*:}"
            is_junk_match_line "$f" "$rest" && continue
            matches+=$'Line '"$ln"$': '"$(get_match_snippet "$rest")"$'\n'
        done < <(grep -Ein "$CONTENT_REGEX" "$f" 2>/dev/null | head -n 20)

        if [[ -n "$matches" ]]; then
            write_info "[MATCH FILE] $f"
            printf "%s" "$matches" | tee -a "$OUTFILE"
        fi
    done < <(find "$base" -xdev -maxdepth "$MAXDEPTH_FIND" -type f 2>/dev/null)
done

# ---------- Writable interesting config locations ----------
write_section "Writable Interesting Locations"

WRITABLE_CHECKS=(
    "/etc"
    "/opt"
    "/srv"
    "/var/www"
    "/usr/local"
    "$HOME"
)

for p in "${WRITABLE_CHECKS[@]}"; do
    [[ ! -e "$p" ]] && continue
    if [[ -w "$p" ]]; then
        write_info "[Writable] $p"
    fi
done

find /etc /opt /srv /var/www /usr/local "$HOME" -maxdepth 3 -type f 2>/dev/null | while read -r f; do
    [[ -w "$f" ]] || continue
    is_excluded_path "$f" && continue
    is_excluded_path_contains "$f" && continue

    bname="$(basename "$f")"
    if printf "%s" "$bname" | grep -Eqi '(conf|cfg|cnf|ini|json|yaml|yml|xml|php|py|rb|pl|sh|service|env|properties)'; then
        write_info "[Writable File] $f"
    fi
done

write_section "Done"
write_info "Single output file: $OUTFILE"

echo
echo "Done."
echo "Report: $OUTFILE"
