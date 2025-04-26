package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m" // Use for found items
	ColorGreen  = "\033[32m" // Use for success messages/counts
	ColorYellow = "\033[33m" // Use for prompts/info messages
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// ASCII Art Banner
const banner = `
     _________
    / ======= \\
   / __________\\
  | ___________ |
  | | -       | |
  | |    GTFO | |
  | |_________| |  <-- CHECKER MODE
  \=____________/
  / '''''''''''' \\
 / ::::::::::::: \\
(_________________)
`

const authorLine = "               :: GTFOCheck Tool by [EragonKashyap11] ::"

// --- GTFObins Lists ---
// (Lists remain the same as the previous version - gtfobinsSuidList, gtfobinsCapList, gtfobinsSudoList)
var gtfobinsSuidList = []string{ /* SUID list */
	"aa-exec", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "aspell",
	"atobm", "awk", "base32", "base64", "basenc", "basez", "bash", "bc", "bridge",
	"busctl", "busybox", "bzip2", "cabal", "capsh", "cat", "chmod", "choom",
	"chown", "chroot", "clamscan", "cmp", "column", "comm", "cp", "cpio",
	"cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl", "cut", "dash",
	"date", "dd", "debugfs", "dialog", "diff", "dig", "distcc", "docker", "dosbox",
	"ed", "efax", "elvish", "emacs", "env", "eqn", "espeak", "expand", "expect",
	"file", "find", "fish", "flock", "fmt", "fold", "gawk", "gdb", "genie",
	"genisoimage", "gimp", "grep", "gtester", "gzip", "hd", "head", "hexdump",
	"highlight", "hping3", "iconv", "install", "ionice", "ip", "irb", "ispell",
	"jjs", "join", "jq", "jrunscript", "julia", "ksh", "ksshell", "kubectl",
	"ld.so", "less", "links", "logsave", "look", "lua", "make", "mawk", "minicom",
	"more", "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge",
	"msguniq", "multitime", "mv", "nasm", "nawk", "ncftp", "nft", "nice", "nl",
	"nm", "nmap", "node", "nohup", "ntpdate", "od", "openssl", "openvpn", "pandoc",
	"paste", "perf", "perl", "pexec", "pg", "php", "pidstat", "pr", "ptx", "python",
	"rc", "readelf", "restic", "rev", "rlwrap", "rsync", "rtorrent", "rview", "rvim",
	"sash", "scanmem", "sed", "setarch", "setfacl", "setlock", "shuf", "smbclient",
	"socat", "soelim", "softlimit", "sort", "sqlite3", "ss", "ssh-agent",
	"ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace",
	"strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh",
	"tee", "terraform", "tftp", "tic", "time", "timeout", "troff", "ul",
	"unexpand", "uniq", "unshare", "unsquashfs", "unzip", "update-alternatives",
	"uudecode", "uuencode", "vagrant", "varnishncsa", "view", "vigr", "vim",
	"vimdiff", "vipw", "w3m", "watch", "wc", "wget", "whiptail", "xargs", "xdotool",
	"xmodmap", "xmore", "xxd", "xz", "yash", "zsh", "zsoelim",
}

var gtfobinsCapList = []string{ /* Capabilities list */
	"gdb", "node", "perl", "php", "python", "rview", "rvim", "view", "vim",
	"vimdiff", "openssl", "tar", "dumpcap",
}

var gtfobinsSudoList = []string{ /* Sudo list */
	"7z", "aa-exec", "ab", "alpine", "ansible-playbook", "ansible-test", "aoss",
	"apache2ctl", "apt-get", "apt", "ar", "aria2c", "arj", "arp", "as", "ascii-xfr",
	"ascii85", "ash", "aspell", "at", "atobm", "awk", "aws", "base32", "base58",
	"base64", "basenc", "basez", "bash", "batcat", "bc", "bconsole", "bpftrace",
	"bridge", "bundle", "bundler", "busctl", "busybox", "byebug", "bzip2", "c89",
	"c99", "cabal", "cancel", "capsh", "cat", "cdist", "certbot", "check_by_ssh",
	"check_cups", "check_log", "check_memory", "check_raid", "check_ssl_cert",
	"check_statusfile", "chmod", "choom", "chown", "chroot", "clamscan", "cmp",
	"cobc", "column", "comm", "composer", "cowsay", "cowthink", "cp", "cpan",
	"cpio", "cpulimit", "crash", "crontab", "csh", "csplit", "csvtool", "cupsfilter",
	"curl", "cut", "dash", "date", "dc", "dd", "debugfs", "dialog", "diff", "dig",
	"distcc", "dmesg", "dmidecode", "dmsetup", "dnf", "docker", "dos2unix", "dosbox",
	"dotnet", "dpkg", "dstat", "dvips", "easy_install", "eb", "ed", "efax", "elvish",
	"emacs", "enscript", "env", "eqn", "espeak", "ex", "exiftool", "expand", "expect",
	"facter", "file", "find", "finger", "fish", "flock", "fmt", "fold", "fping",
	"ftp", "gawk", "gcc", "gcloud", "gcore", "gdb", "gem", "genie", "genisoimage",
	"ghc", "ghci", "gimp", "ginsh", "git", "grc", "grep", "gtester", "gzip", "hd",
	"head", "hexdump", "highlight", "hping3", "iconv", "iftop", "install", "ionice",
	"ip", "irb", "ispell", "jjs", "joe", "join", "journalctl", "jq", "jrunscript",
	"jtag", "julia", "knife", "ksh", "ksshell", "ksu", "kubectl", "latex",
	"latexmk", "ld.so", "ldconfig", "less", "lftp", "links", "ln", "loginctl",
	"logsave", "look", "lp", "ltrace", "lua", "lualatex", "luatex", "lwp-download",
	"lwp-request", "mail", "make", "man", "mawk", "minicom", "more", "mosquitto",
	"mount", "msfconsole", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge",
	"msguniq", "mtr", "multitime", "mv", "mysql", "nano", "nasm", "nawk", "nc",
	"ncdu", "ncftp", "neofetch", "nft", "nice", "nl", "nm", "nmap", "node", "nohup",
	"npm", "nroff", "nsenter", "ntpdate", "octave", "od", "openssl", "openvpn",
	"openvt", "opkg", "pandoc", "paste", "pax", "pdb", "pdflatex", "pdftex", "perf",
	"perl", "perlbug", "pexec", "pg", "php", "pic", "pico", "pidstat", "pip",
	"pkexec", "pkg", "posh", "pr", "pry", "psftp", "psql", "ptx", "puppet", "pwsh",
	"python", "rake", "rc", "readelf", "red", "redcarpet", "redis", "restic", "rev",
	"rlogin", "rlwrap", "rpm", "rpmdb", "rpmquery", "rpmverify", "rsync", "rtorrent",
	"ruby", "run-mailcap", "run-parts", "runscript", "rview", "rvim", "sash",
	"scanmem", "scp", "screen", "script", "scrot", "sed", "service", "setarch",
	"setfacl", "setlock", "sftp", "sg", "shuf", "slsh", "smbclient", "snap", "socat",
	"socket", "soelim", "softlimit", "sort", "split", "sqlite3", "sqlmap", "ss",
	"ssh-agent", "ssh-keygen", "ssh-keyscan", "ssh", "sshpass", "start-stop-daemon",
	"stdbuf", "strace", "strings", "su", "sudo", "sysctl", "systemctl",
	"systemd-resolve", "tac", "tail", "tar", "task", "taskset", "tasksh", "tbl",
	"tclsh", "tcpdump", "tdbtool", "tee", "telnet", "terraform", "tex", "tftp",
	"tic", "time", "timedatectl", "timeout", "tmate", "tmux", "top", "torify",
	"torsocks", "troff", "tshark", "ul", "unexpand", "uniq", "unshare", "unsquashfs",
	"unzip", "update-alternatives", "uudecode", "uuencode", "vagrant", "valgrind",
	"varnishncsa", "vi", "view", "vigr", "vim", "vimdiff", "vipw", "virsh",
	"volatility", "w3m", "wall", "watch", "wc", "wget", "whiptail", "whois",
	"wireshark", "wish", "xargs", "xdg-user-dir", "xdotool", "xelatex", "xetex",
	"xmodmap", "xmore", "xpad", "xxd", "xz", "yarn", "yash", "yelp", "yum",
	"zathura", "zip", "zsh", "zsoelim", "zypper",
}

// --- Helper Functions ---
// (Helper functions remain the same: createLookupMap, extractBasename, extractCapBinaryBasename, extractSudoBinaryBasename, promptUser)
func createLookupMap(list []string) map[string]bool {
	lookupMap := make(map[string]bool, len(list))
	for _, item := range list {
		lookupMap[item] = true
	}
	return lookupMap
}

func extractBasename(fullPath string) string {
	return filepath.Base(strings.TrimSpace(fullPath))
}

func extractCapBinaryBasename(line string) (string, bool) {
	parts := strings.SplitN(line, " = ", 2)
	if len(parts) < 1 {
		return "", false
	}
	pathPart := strings.TrimSpace(parts[0])
	if pathPart == "" {
		return "", false
	}
	return filepath.Base(pathPart), true
}

func extractSudoBinaryBasename(line string) (string, bool) {
	cleanLine := strings.TrimSpace(line)
	if strings.HasPrefix(cleanLine, "#") || cleanLine == "" || strings.HasPrefix(cleanLine, "User ") || strings.HasPrefix(cleanLine, "Matching Defaults entries") {
		return "", false // Ignore comments, empty lines, and header lines
	}

	potentialCommands := []string{}
	parts := strings.Split(cleanLine, ",") // Split by comma for multiple commands
	lastPart := cleanLine                  // Default to the whole line if no comma
	if len(parts) > 0 {
		lastPart = parts[len(parts)-1] // Focus on the last command specifier usually
	}

	fields := strings.Fields(lastPart) // Split the relevant part by whitespace
	for _, field := range fields {
		trimmedField := strings.Trim(field, "()") // Remove potential surrounding parens like (root)
		// Check if it looks like a path or is just 'ALL'
		if strings.HasPrefix(trimmedField, "/") || trimmedField == "ALL" {
			potentialCommands = append(potentialCommands, trimmedField)
		} else {
			// Could be a simple command name without path, add it too
			potentialCommands = append(potentialCommands, trimmedField)
		}
	}

	// Return the *last* identified potential command/path
	for i := len(potentialCommands) - 1; i >= 0; i-- {
		cmd := strings.TrimSpace(potentialCommands[i])
		if cmd != "" {
			// Return the base name for map lookup
			return filepath.Base(cmd), true
		}
	}

	return "", false
}

func promptUser(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// --- Main Logic ---

func main() {
	// --- Print Banner ---
	fmt.Printf("%s%s%s\n", ColorCyan, banner, ColorReset)
	fmt.Printf("%s%s%s\n", ColorYellow, authorLine, ColorReset)
	fmt.Println() // Add a newline for spacing

	// --- Command Line Flags ---
	checkTypeFlag := flag.String("type", "", "Type of check: 'suid', 'cap', or 'sudo'. (Prompts if unset)")
	inputFileFlag := flag.String("file", "", "Input file path. (Prompts if unset)")

	flag.Usage = func() {
		// (Usage message remains the same as previous version)
		fmt.Fprintf(os.Stderr, "%sUsage: %s%s [flags]\n\n", ColorBold, os.Args[0], ColorReset)
		fmt.Fprintf(os.Stderr, "Checks SUID, Capability, or Sudo privilege output against GTFObins lists.\n")
		fmt.Fprintf(os.Stderr, "Prompts for check type and input source if flags are not provided.\n\n")
		fmt.Fprintf(os.Stderr, "%sFlags:%s\n", ColorBold, ColorReset)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n%sExamples:%s\n", ColorBold, ColorReset)
		fmt.Fprintf(os.Stderr, "  %s# Interactive prompts:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  ./gtfocheck\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Check SUIDs from find command piped in:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  find / -perm -u=s -type f 2>/dev/null | ./gtfocheck -type suid\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Check SUIDs from a saved file:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  ./gtfocheck -type suid -file find_output.txt\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Check capabilities from getcap command piped in:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  /usr/sbin/getcap -r / 2>/dev/null | ./gtfocheck -type cap\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Check capabilities from a saved file:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  ./gtfocheck -type cap -file getcap_output.txt\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Check sudo rules from sudo -l output piped in:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  sudo -l | ./gtfocheck -type sudo\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Check sudo rules from a saved file:%s\n", ColorCyan, ColorReset)
		fmt.Fprintf(os.Stderr, "  ./gtfocheck -type sudo -file sudo_output.txt\n\n")
	}
	flag.Parse()

	// --- Determine Check Type (Flag or Interactive) ---
	checkType := strings.ToLower(*checkTypeFlag)
	if checkType == "" {
		fmt.Printf("%s--- Select Check Type ---%s\n", ColorBold, ColorReset)
		checkType = promptUser(fmt.Sprintf("%sEnter check type (suid, cap, sudo): %s", ColorYellow, ColorReset))
		checkType = strings.ToLower(checkType)
	}

	// --- Select GTFObins List and Parsing Function ---
	var gtfobinsMap map[string]bool
	var extractFunc func(string) (string, bool)
	var checkDescription string

	switch checkType {
	case "suid":
		gtfobinsMap = createLookupMap(gtfobinsSuidList)
		extractFunc = func(line string) (string, bool) {
			if line == "" { return "", false }
			return extractBasename(line), true
		}
		checkDescription = "SUID"
	case "cap":
		gtfobinsMap = createLookupMap(gtfobinsCapList)
		extractFunc = extractCapBinaryBasename
		checkDescription = "Capability"
	case "sudo":
		gtfobinsMap = createLookupMap(gtfobinsSudoList)
		extractFunc = extractSudoBinaryBasename
		checkDescription = "Sudo"
	default:
		fmt.Fprintf(os.Stderr, "%sError: Invalid check type %q. Use 'suid', 'cap', or 'sudo'.%s\n", ColorRed, checkType, ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	// --- Determine Input Source (Flag or Interactive) ---
	var inputReader io.Reader
	var sourceDesc string
	inputFile := *inputFileFlag

	if inputFile == "" {
		fmt.Printf("\n%s--- Select Input Source ---%s\n", ColorBold, ColorReset)
		inputChoice := promptUser(fmt.Sprintf("%sRead from file or pipe/paste input? (file/paste): %s", ColorYellow, ColorReset))
		if strings.ToLower(inputChoice) == "file" {
			inputFile = promptUser(fmt.Sprintf("%sEnter input filename: %s", ColorYellow, ColorReset))
		} else {
			inputReader = os.Stdin
			sourceDesc = "stdin (paste input below and press Ctrl+D when done)"
			fmt.Printf("%sReading input from %s%s%s\n", ColorYellow, ColorBold, sourceDesc, ColorReset)
		}
	}

	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError opening file %q: %v%s\n", ColorRed, inputFile, err, ColorReset)
			os.Exit(1)
		}
		defer file.Close()
		inputReader = file
		sourceDesc = fmt.Sprintf("file: %s%s%s", ColorBold, inputFile, ColorReset)
		fmt.Printf("%sReading input from %s%s\n", ColorYellow, sourceDesc, ColorReset)
	} else if inputReader == nil {
		fmt.Fprintf(os.Stderr, "%sError: No input source selected.%s\n", ColorRed, ColorReset)
		os.Exit(1)
	}

	// --- Process Input ---
	foundItems := []string{}
	scanner := bufio.NewScanner(inputReader)

	fmt.Printf("\n%s--- Checking for potential GTFObins %s matches ---%s\n", ColorBold, checkDescription, ColorReset)

	for scanner.Scan() {
		line := scanner.Text()
		baseName, ok := extractFunc(line)

		if !ok || baseName == "" {
			continue
		}

		if _, found := gtfobinsMap[baseName]; found {
			foundItems = append(foundItems, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%sError reading input: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	// --- Print Results ---
	if len(foundItems) > 0 {
		// Use Green for the summary count
		fmt.Printf("\n%s%sFound %d potential GTFObins %s matches:%s\n", ColorGreen, ColorBold, len(foundItems), checkDescription, ColorReset)
		fmt.Printf("%s-----------------------------------------%s\n", ColorGreen, ColorReset)
		// Use Red for highlighting the actual matched lines
		for _, item := range foundItems {
			fmt.Printf("%s%s%s\n", ColorRed, item, ColorReset) // Changed ColorYellow to ColorRed here
		}
		fmt.Printf("%s-----------------------------------------%s\n", ColorGreen, ColorReset)
		fmt.Printf("Refer to GTFObins (%shttps://gtfobins.github.io/%s) for exploitation details.\n", ColorCyan, ColorReset)

		// Keep the specific warning for sudo ALL findings, now also in Red
		if checkType == "sudo" {
			hasSudoAll := false
			for _, item := range foundItems {
				 cleanedItem := strings.ToUpper(strings.Join(strings.Fields(item), " "))
				 if strings.Contains(cleanedItem, " NOPASSWD: ALL") || cleanedItem == "(ALL) ALL" || cleanedItem == "(ROOT) ALL" || strings.HasSuffix(cleanedItem, " = ALL") || strings.Contains(cleanedItem, "(ALL : ALL) ALL") {
					 hasSudoAll = true
					 break
				 }
			}
			if hasSudoAll {
				fmt.Printf("\n%s%sWARNING: Found rule granting 'ALL' privileges. This is highly permissive!%s\n", ColorRed, ColorBold, ColorReset)
			}
		}

	} else {
		// Use Yellow for the "not found" message
		fmt.Printf("\n%sNo potential GTFObins %s matches found based on the provided list.%s\n", ColorYellow, checkDescription, ColorReset)
	}
}
