#!/bin/sh

# ==============================================================================
# PrivEsc Service Hunter
# Scans Linux and FreeBSD environments for vulnerable service configurations.
# ==============================================================================

echo "========================================================================"
echo "[*] Hunting for vulnerable services..."
echo "========================================================================"

# Helper function to determine how the service can be triggered
get_triggers() {
    file_path="$1"
    svc_name=$(basename "$file_path")
    triggers=""

    # 1. Sudo Trigger: Can we run systemctl or service commands without a password?
    # (Uses -n to prevent blocking/prompting for a password)
    if sudo -n -l 2>/dev/null | grep -qiE "(systemctl.*$svc_name|service.*$svc_name|NOPASSWD:.*ALL)"; then
        triggers="$triggers[Sudo Start/Restart] "
    fi

    # 2. Auto-Restart Trigger: Will it revive itself if killed? (systemd specific)
    if grep -qE "^Restart=(always|on-failure)" "$file_path" 2>/dev/null; then
        triggers="$triggers[Auto-Restart on Crash (Kill it)] "
    fi

    # 3. Boot Trigger: Does it run on startup?
    # Linux (systemd) check
    if [ -d /etc/systemd/system/multi-user.target.wants ] && ls -la /etc/systemd/system/multi-user.target.wants/ 2>/dev/null | grep -q "$svc_name"; then
        triggers="$triggers[Reboot] "
    fi
    # FreeBSD / Legacy check
    svc_base=$(echo "$svc_name" | cut -d. -f1)
    if grep -qE "^${svc_base}_enable=\"YES\"" /etc/rc.conf 2>/dev/null; then
         triggers="$triggers[Reboot] "
    fi

    # Default fallback
    if [ -z "$triggers" ]; then
        echo "[Manual/Unknown]"
    else
        echo "$triggers"
    fi
}

# Main scanning loop
find /etc/systemd/system/ /lib/systemd/system/ /etc/init.d/ /usr/local/etc/rc.d/ /etc/rc.d/ -type f 2>/dev/null | while read -r svc_file; do
    
    vuln_class=""
    bin_path=""

    # 1. Check if the configuration script/file itself is writable
    if [ -w "$svc_file" ]; then
        vuln_class="$vuln_class[Writable Service Config] "
    fi

    # 2. Extract the execution path
    # Systemd extraction
    if grep -q "^ExecStart=" "$svc_file" 2>/dev/null; then
        # Grab the first argument after ExecStart=
        bin_path=$(grep "^ExecStart=" "$svc_file" | cut -d '=' -f 2- | awk '{print $1}')
        # Strip quotes if they exist
        bin_path=$(echo "$bin_path" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    
    # Init.d / rc.d extraction (Harder to parse dynamically, flagged for manual review)
    elif grep -qE "^#!/bin/sh|^#!/bin/bash" "$svc_file" 2>/dev/null; then
        bin_path="N/A (Shell Script - Read manually)"
    fi

    # 3. Analyze the binary path for vulnerabilities
    if [ -n "$bin_path" ] && [ "$bin_path" != "N/A (Shell Script - Read manually)" ]; then
        
        # Check for Relative Paths (Doesn't start with '/')
        case "$bin_path" in
            /*) 
                # Absolute path: Check permissions of the binary and its parent directory
                if [ -e "$bin_path" ]; then
                    if [ -w "$bin_path" ]; then
                        vuln_class="$vuln_class[Writable Binary Path] "
                    fi
                    
                    bin_dir=$(dirname "$bin_path")
                    if [ -w "$bin_dir" ]; then
                        vuln_class="$vuln_class[Writable Binary Folder] "
                    fi
                fi
                ;;
            *) 
                # Relative path means PATH hijacking is possible
                vuln_class="$vuln_class[Relative Path (PATH Hijack)] "
                ;;
        esac

        # Check for Wildcards anywhere in the ExecStart string
        if grep -q "^ExecStart=.*[*]" "$svc_file" 2>/dev/null; then
            vuln_class="$vuln_class[Wildcard (*) in Path] "
        fi
    fi

    # 4. Output generation (Only display if a vulnerability class was appended)
    if [ -n "$vuln_class" ]; then
        echo "------------------------------------------------------------------------"
        echo "Service:  $(basename "$svc_file") ($svc_file)"
        echo "Binary:   $bin_path"
        echo "Vuln:     $vuln_class"
        echo "Trigger:  $(get_triggers "$svc_file")"
    fi

done

echo "------------------------------------------------------------------------"
echo "[+] Scan Complete."
