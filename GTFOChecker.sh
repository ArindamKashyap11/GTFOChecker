#!/bin/bash

# ANSI Color Codes
COLOR_RESET='\033[0m'
COLOR_RED='\033[31m'   # Use for found items
COLOR_GREEN='\033[32m' # Use for success messages/counts
COLOR_YELLOW='\033[33m'# Use for prompts/info messages
COLOR_CYAN='\033[36m'
COLOR_BOLD='\033[1m'

# --- GTFObins Lists (as Bash Arrays) ---
gtfobinsSuidList=(
	"aa-exec" "agetty" "alpine" "ar" "arj" "arp" "as" "ascii-xfr" "aspell"
	"atobm" "awk" "base32" "base64" "basenc" "basez" "bash" "bc" "bridge"
	"busctl" "busybox" "bzip2" "cabal" "capsh" "cat" "chmod" "choom"
	"chown" "chroot" "clamscan" "cmp" "column" "comm" "cp" "cpio"
	"cpulimit" "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash"
	"date" "dd" "debugfs" "dialog" "diff" "dig" "distcc" "docker" "dosbox"
	"ed" "efax" "elvish" "emacs" "env" "eqn" "espeak" "expand" "expect"
	"file" "find" "fish" "flock" "fmt" "fold" "gawk" "gdb" "genie"
	"genisoimage" "gimp" "grep" "gtester" "gzip" "hd" "head" "hexdump"
	"highlight" "hping3" "iconv" "install" "ionice" "ip" "irb" "ispell"
	"jjs" "join" "jq" "jrunscript" "julia" "ksh" "ksshell" "kubectl"
	"ld.so" "less" "links" "logsave" "look" "lua" "make" "mawk" "minicom"
	"more" "mosquitto" "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge"
	"msguniq" "multitime" "mv" "nasm" "nawk" "ncftp" "nft" "nice" "nl"
	"nm" "nmap" "node" "nohup" "ntpdate" "od" "openssl" "openvpn" "pandoc"
	"paste" "perf" "perl" "pexec" "pg" "php" "pidstat" "pr" "ptx" "python"
	"rc" "readelf" "restic" "rev" "rlwrap" "rsync" "rtorrent" "rview" "rvim"
	"sash" "scanmem" "sed" "setarch" "setfacl" "setlock" "shuf" "smbclient"
	"socat" "soelim" "softlimit" "sort" "sqlite3" "ss" "ssh-agent"
	"ssh-keygen" "ssh-keyscan" "sshpass" "start-stop-daemon" "stdbuf" "strace"
	"strings" "sysctl" "systemctl" "tac" "tail" "taskset" "tbl" "tclsh"
	"tee" "terraform" "tftp" "tic" "time" "timeout" "troff" "ul"
	"unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives"
	"uudecode" "uuencode" "vagrant" "varnishncsa" "view" "vigr" "vim"
	"vimdiff" "vipw" "w3m" "watch" "wc" "wget" "whiptail" "xargs" "xdotool"
	"xmodmap" "xmore" "xxd" "xz" "yash" "zsh" "zsoelim"
)

gtfobinsCapList=(
    "gdb" "node" "perl" "php" "python" "rview" "rvim" "view" "vim"
	"vimdiff" "openssl" "tar" "dumpcap"
)

gtfobinsSudoList=(
	"7z" "aa-exec" "ab" "alpine" "ansible-playbook" "ansible-test" "aoss"
	"apache2ctl" "apt-get" "apt" "ar" "aria2c" "arj" "arp" "as" "ascii-xfr"
	"ascii85" "ash" "aspell" "at" "atobm" "awk" "aws" "base32" "base58"
	"base64" "basenc" "basez" "bash" "batcat" "bc" "bconsole" "bpftrace"
	"bridge" "bundle" "bundler" "busctl" "busybox" "byebug" "bzip2" "c89"
	"c99" "cabal" "cancel" "capsh" "cat" "cdist" "certbot" "check_by_ssh"
	"check_cups" "check_log" "check_memory" "check_raid" "check_ssl_cert"
	"check_statusfile" "chmod" "choom" "chown" "chroot" "clamscan" "cmp"
	"cobc" "column" "comm" "composer" "cowsay" "cowthink" "cp" "cpan"
	"cpio" "cpulimit" "crash" "crontab" "csh" "csplit" "csvtool" "cupsfilter"
	"curl" "cut" "dash" "date" "dc" "dd" "debugfs" "dialog" "diff" "dig"
	"distcc" "dmesg" "dmidecode" "dmsetup" "dnf" "docker" "dos2unix" "dosbox"
	"dotnet" "dpkg" "dstat" "dvips" "easy_install" "eb" "ed" "efax" "elvish"
	"emacs" "enscript" "env" "eqn" "espeak" "ex" "exiftool" "expand" "expect"
	"facter" "file" "find" "finger" "fish" "flock" "fmt" "fold" "fping"
	"ftp" "gawk" "gcc" "gcloud" "gcore" "gdb" "gem" "genie" "genisoimage"
	"ghc" "ghci" "gimp" "ginsh" "git" "grc" "grep" "gtester" "gzip" "hd"
	"head" "hexdump" "highlight" "hping3" "iconv" "iftop" "install" "ionice"
	"ip" "irb" "ispell" "jjs" "joe" "join" "journalctl" "jq" "jrunscript"
	"jtag" "julia" "knife" "ksh" "ksshell" "ksu" "kubectl" "latex"
	"latexmk" "ld.so" "ldconfig" "less" "lftp" "links" "ln" "loginctl"
	"logsave" "look" "lp" "ltrace" "lua" "lualatex" "luatex" "lwp-download"
	"lwp-request" "mail" "make" "man" "mawk" "minicom" "more" "mosquitto"
	"mount" "msfconsole" "msgattrib" "msgcat" "msgconv" "msgfilter" "msgmerge"
	"msguniq" "mtr" "multitime" "mv" "mysql" "nano" "nasm" "nawk" "nc"
	"ncdu" "ncftp" "neofetch" "nft" "nice" "nl" "nm" "nmap" "node" "nohup"
	"npm" "nroff" "nsenter" "ntpdate" "octave" "od" "openssl" "openvpn"
	"openvt" "opkg" "pandoc" "paste" "pax" "pdb" "pdflatex" "pdftex" "perf"
	"perl" "perlbug" "pexec" "pg" "php" "pic" "pico" "pidstat" "pip"
	"pkexec" "pkg" "posh" "pr" "pry" "psftp" "psql" "ptx" "puppet" "pwsh"
	"python" "rake" "rc" "readelf" "red" "redcarpet" "redis" "restic" "rev"
	"rlogin" "rlwrap" "rpm" "rpmdb" "rpmquery" "rpmverify" "rsync" "rtorrent"
	"ruby" "run-mailcap" "run-parts" "runscript" "rview" "rvim" "sash"
	"scanmem" "scp" "screen" "script" "scrot" "sed" "service" "setarch"
	"setfacl" "setlock" "sftp" "sg" "shuf" "slsh" "smbclient" "snap" "socat"
	"socket" "soelim" "softlimit" "sort" "split" "sqlite3" "sqlmap" "ss"
	"ssh-agent" "ssh-keygen" "ssh-keyscan" "ssh" "sshpass" "start-stop-daemon"
	"stdbuf" "strace" "strings" "su" "sudo" "sysctl" "systemctl"
	"systemd-resolve" "tac" "tail" "tar" "task" "taskset" "tasksh" "tbl"
	"tclsh" "tcpdump" "tdbtool" "tee" "telnet" "terraform" "tex" "tftp"
	"tic" "time" "timedatectl" "timeout" "tmate" "tmux" "top" "torify"
	"torsocks" "troff" "tshark" "ul" "unexpand" "uniq" "unshare" "unsquashfs"
	"unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "valgrind"
	"varnishncsa" "vi" "view" "vigr" "vim" "vimdiff" "vipw" "virsh"
	"volatility" "w3m" "wall" "watch" "wc" "wget" "whiptail" "whois"
	"wireshark" "wish" "xargs" "xdg-user-dir" "xdotool" "xelatex" "xetex"
	"xmodmap" "xmore" "xpad" "xxd" "xz" "yarn" "yash" "yelp" "yum"
	"zathura" "zip" "zsh" "zsoelim" "zypper"
)


# --- Helper Functions ---

# Function to display usage information
usage() {
    cat << EOF
${COLOR_BOLD}Usage: $(basename "$0")${COLOR_RESET} [flags]

Checks SUID, Capability, or Sudo privilege output against GTFObins lists.
Prompts for check type and input source if flags are not provided.

${COLOR_BOLD}Flags:${COLOR_RESET}
  -t, --type      Type of check: 'suid', 'cap', or 'sudo'.
  -f, --file      Input file path. Reads from pipe/stdin if not set.
  -h, --help      Display this help message.

${COLOR_BOLD}Examples:${COLOR_RESET}
  ${COLOR_CYAN}# Interactive prompts:${COLOR_RESET}
  ./gtfocheck.sh

  ${COLOR_CYAN}# Check SUIDs from find command piped in:${COLOR_RESET}
  find / -perm -u=s -type f 2>/dev/null | ./gtfocheck.sh -t suid

  ${COLOR_CYAN}# Check capabilities from a saved file:${COLOR_RESET}
  ./gtfocheck.sh -t cap -f getcap_output.txt

  ${COLOR_CYAN}# Check sudo rules from sudo -l output piped in:${COLOR_RESET}
  sudo -l | ./gtfocheck.sh -t sudo
EOF
}

# Function to check if an item exists in an array
# $1: item to check
# $2: array name to check in (passed by name reference)
contains_element() {
    local item="$1"
    local -n arr="$2" # Name reference to the array
    for element in "${arr[@]}"; do
        if [[ "$element" == "$item" ]]; then
            return 0 # Found
        fi
    done
    return 1 # Not found
}


# --- Main Logic ---

# --- Argument Parsing ---
CHECK_TYPE=""
INPUT_FILE=""

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -t|--type)
        CHECK_TYPE="$2"
        shift; shift
        ;;
        -f|--file)
        INPUT_FILE="$2"
        shift; shift
        ;;
        -h|--help)
        usage
        exit 0
        ;;
        *) # unknown option
        echo -e "${COLOR_RED}Unknown option: $1${COLOR_RESET}"
        usage
        exit 1
        ;;
    esac
done

# --- Print Banner ---
echo -e "${COLOR_CYAN}"
cat << "EOF"
     _________
    / ======= \
   / __________\
  | ___________ |
  | | -       | |
  | |    GTFO | |
  | |_________| |  <-- CHECKER MODE
  \=____________/
  / ''''''''''' \
 / ::::::::::::: \
(_________________)
EOF
echo -e "${COLOR_YELLOW}               :: GTFOCheck Tool by [EragonKashyap11] ::${COLOR_RESET}\n"


# --- Determine Check Type (Flag or Interactive) ---
if [[ -z "$CHECK_TYPE" ]]; then
    echo -e "${COLOR_BOLD}--- Select Check Type ---${COLOR_RESET}"
    read -p "$(echo -e ${COLOR_YELLOW}"Enter check type (suid, cap, sudo): "${COLOR_RESET})" CHECK_TYPE
fi
CHECK_TYPE=$(echo "$CHECK_TYPE" | tr '[:upper:]' '[:lower:]')


# --- Select GTFObins List and Parsing Function ---
declare -a list_to_check
check_description=""

case "$CHECK_TYPE" in
    suid)
        list_to_check=("${gtfobinsSuidList[@]}")
        check_description="SUID"
        ;;
    cap)
        list_to_check=("${gtfobinsCapList[@]}")
        check_description="Capability"
        ;;
    sudo)
        list_to_check=("${gtfobinsSudoList[@]}")
        check_description="Sudo"
        ;;
    *)
        echo -e "${COLOR_RED}Error: Invalid check type \"$CHECK_TYPE\". Use 'suid', 'cap', or 'sudo'.${COLOR_RESET}" >&2
        exit 1
        ;;
esac

# --- Determine Input Source ---
INPUT_READER="/dev/stdin" # Default to stdin for pipes
SOURCE_DESC="stdin (paste input below and press Ctrl+D when done)"

if [[ -n "$INPUT_FILE" ]]; then
    if [[ ! -f "$INPUT_FILE" ]]; then
        echo -e "${COLOR_RED}Error: Input file not found at '$INPUT_FILE'${COLOR_RESET}" >&2
        exit 1
    fi
    INPUT_READER="$INPUT_FILE"
    SOURCE_DESC="file: ${COLOR_BOLD}${INPUT_FILE}${COLOR_RESET}"
elif [[ -t 0 ]]; then # Check if stdin is a terminal (i.e., not a pipe)
    echo -e "\n${COLOR_BOLD}--- Select Input Source ---${COLOR_RESET}"
    read -p "$(echo -e ${COLOR_YELLOW}"Read from file or paste input? (file/paste): "${COLOR_RESET})" input_choice
    input_choice=$(echo "$input_choice" | tr '[:upper:]' '[:lower:]')
    if [[ "$input_choice" == "file" ]]; then
        read -p "$(echo -e ${COLOR_YELLOW}"Enter input filename: "${COLOR_RESET})" INPUT_FILE
        if [[ ! -f "$INPUT_FILE" ]]; then
            echo -e "${COLOR_RED}Error: Input file not found at '$INPUT_FILE'${COLOR_RESET}" >&2
            exit 1
        fi
        INPUT_READER="$INPUT_FILE"
        SOURCE_DESC="file: ${COLOR_BOLD}${INPUT_FILE}${COLOR_RESET}"
    fi
fi

# --- Process Input ---
found_items=()
echo -e "${COLOR_YELLOW}Reading input from ${SOURCE_DESC}${COLOR_RESET}"
echo -e "\n${COLOR_BOLD}--- Checking for potential GTFObins $check_description matches ---${COLOR_RESET}"

while IFS= read -r line; do
    # Ignore empty lines
    [[ -z "$line" ]] && continue

    base_name=""
    # Extract basename based on the check type
    case "$CHECK_TYPE" in
        suid)
            # Input is just a path, e.g., /usr/bin/find
            base_name=$(basename "$line")
            ;;
        cap)
            # Input is like: /usr/bin/gdb = cap_sys_ptrace+ep
            path_part=$(echo "$line" | awk -F' = ' '{print $1}')
            base_name=$(basename "$path_part")
            ;;
        sudo)
            # Input is a line from `sudo -l`
            # Heuristic: find the last field, which is often the command path
            last_field=$(echo "$line" | awk '{print $NF}')
            base_name=$(basename "$last_field")
            ;;
    esac

    if [[ -n "$base_name" ]]; then
        if contains_element "$base_name" list_to_check; then
            found_items+=("$line")
        fi
    fi
done < "$INPUT_READER"


# --- Print Results ---
if (( ${#found_items[@]} > 0 )); then
    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}Found ${#found_items[@]} potential GTFObins $check_description matches:${COLOR_RESET}"
    echo -e "${COLOR_GREEN}-----------------------------------------${COLOR_RESET}"
    # Print each found item in Red
    for item in "${found_items[@]}"; do
        echo -e "${COLOR_RED}${item}${COLOR_RESET}"
    done
    echo -e "${COLOR_GREEN}-----------------------------------------${COLOR_RESET}"
    echo -e "Refer to GTFObins (${COLOR_CYAN}https://gtfobins.github.io/${COLOR_RESET}) for exploitation details."

    # Specific warning for sudo ALL findings
    if [[ "$CHECK_TYPE" == "sudo" ]]; then
        for item in "${found_items[@]}"; do
            # Check for common 'ALL' privilege patterns
            if echo "$item" | grep -Eqi "NOPASSWD: ALL|\(ALL\) ALL|\(ROOT\) ALL|= ALL|\(ALL : ALL\) ALL"; then
                echo -e "\n${COLOR_RED}${COLOR_BOLD}WARNING: Found rule granting 'ALL' privileges. This is highly permissive!${COLOR_RESET}"
                break # Show warning only once
            fi
        done
    fi
else
    echo -e "\n${COLOR_YELLOW}No potential GTFObins $check_description matches found based on the provided list.${COLOR_RESET}"
fi
