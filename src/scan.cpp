#include "scan.hpp"
#include <glib/gstdio.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

const char *severity_name(Severity s) {
    switch (s) {
        case SEV_OK:       return "OK";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
    }
    return "?";
}

const char *severity_color(Severity s) {
    switch (s) {
        case SEV_OK:       return "#2e7d32"; /* green  */
        case SEV_LOW:      return "#0277bd"; /* blue   */
        case SEV_MEDIUM:   return "#f9a825"; /* amber  */
        case SEV_HIGH:     return "#e65100"; /* orange */
        case SEV_CRITICAL: return "#c62828"; /* red    */
    }
    return "#000000";
}

static void finding_free(gpointer p) {
    Finding *f = static_cast<Finding *>(p);
    if (!f) return;
    g_free(f->category);
    g_free(f->title);
    g_free(f->detail);
    g_free(f->suggestion);
    g_free(f->fix_command);
    g_free(f);
}

/* Append a finding to the report and bump the severity counter. */
static void add_finding(ScanReport *r, const char *cat, const char *title,
                        Severity sev, const char *detail,
                        const char *suggestion, const char *fix) {
    Finding *f = g_new0(Finding, 1);
    f->category    = g_strdup(cat);
    f->title       = g_strdup(title);
    f->severity    = sev;
    f->detail      = g_strdup(detail ? detail : "");
    f->suggestion  = g_strdup(suggestion ? suggestion : "");
    f->fix_command = fix ? g_strdup(fix) : NULL;
    g_ptr_array_add(r->items, f);
    r->counts[sev]++;
}

/* Run a shell command, return stdout (caller frees). NULL on spawn error. */
static char *run_cmd(const char *cmd) {
    char *out = NULL;
    gint  status = 0;
    GError *err = NULL;
    const char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    if (!g_spawn_sync(NULL, (gchar **)argv, NULL,
                      G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                      &out, NULL, &status, &err)) {
        if (err) g_error_free(err);
        return NULL;
    }
    return out; /* may be empty string */
}

/* TRUE if a command is found on PATH. */
static gboolean have_cmd(const char *name) {
    char *path = g_find_program_in_path(name);
    gboolean ok = path != NULL;
    g_free(path);
    return ok;
}

static char *chomp_dup(const char *s) {
    if (!s) return g_strdup("");
    char *d = g_strdup(s);
    g_strstrip(d);
    return d;
}

/* ------------------------------------------------------------------ */
/* Individual checks. Each takes the report and appends findings.      */
/* ------------------------------------------------------------------ */

static void check_updates(ScanReport *r) {
    if (have_cmd("apt-get")) {
        char *out = run_cmd("apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null "
                            "| grep -c '^Inst' ");
        int pending = out ? atoi(out) : 0;
        g_free(out);
        char *sec = run_cmd("apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null "
                            "| grep -i '^Inst' | grep -ci security");
        int secn = sec ? atoi(sec) : 0;
        g_free(sec);
        if (pending == 0) {
            add_finding(r, "Updates", "System packages up to date", SEV_OK,
                        "No pending package upgrades detected.", "", NULL);
        } else {
            char d[256];
            g_snprintf(d, sizeof d, "%d package(s) can be upgraded, "
                       "%d of which are security updates.", pending, secn);
            add_finding(r, "Updates", "Pending package updates",
                        secn > 0 ? SEV_HIGH : SEV_MEDIUM, d,
                        "Apply outstanding updates, especially security ones. "
                        "Reboot afterwards if the kernel was updated.",
                        "sudo apt-get update && sudo apt-get upgrade -y");
        }
    }
    /* Unattended-upgrades present? */
    if (have_cmd("apt-get")) {
        char *u = run_cmd("dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii'");
        int has = u ? atoi(u) : 0;
        g_free(u);
        if (!has) {
            add_finding(r, "Updates", "Automatic security updates not installed",
                        SEV_LOW, "The unattended-upgrades package is not installed.",
                        "Install and enable unattended-upgrades so security "
                        "patches are applied automatically.",
                        "sudo apt-get install -y unattended-upgrades && "
                        "sudo dpkg-reconfigure -plow unattended-upgrades");
        } else {
            add_finding(r, "Updates", "Automatic security updates available",
                        SEV_OK, "unattended-upgrades is installed.", "", NULL);
        }
    }
}

static void check_firewall(ScanReport *r) {
    if (have_cmd("ufw")) {
        /* `ufw status` needs root; capture stderr so we can tell "inactive"
         * apart from "permission denied" and avoid a false HIGH finding. */
        char *out = run_cmd("ufw status 2>&1 | head -1");
        char *s = chomp_dup(out);
        g_free(out);
        if (g_ascii_strcasecmp(s, "") == 0 ||
            g_strstr_len(s, -1, "need to be root") ||
            g_strstr_len(s, -1, "permission") ||
            g_strstr_len(s, -1, "ERROR")) {
            add_finding(r, "Firewall", "Firewall status unknown (needs root)",
                        SEV_LOW, "UFW is installed but its status could not be "
                        "read without root.",
                        "Re-run Envision as root (via pkexec) to verify the "
                        "firewall is active.", NULL);
            g_free(s);
            return;
        }
        if (g_strstr_len(s, -1, "active")) {
            r->firewall_active = TRUE;
            add_finding(r, "Firewall", "UFW firewall is active", SEV_OK,
                        s, "", NULL);
        } else {
            add_finding(r, "Firewall", "Firewall inactive", SEV_HIGH,
                        "UFW is installed but not active.",
                        "Enable a default-deny firewall. Allow only services "
                        "you intentionally expose.",
                        "sudo ufw default deny incoming && "
                        "sudo ufw default allow outgoing && sudo ufw enable");
        }
        g_free(s);
    } else if (have_cmd("firewall-cmd")) {
        char *out = run_cmd("firewall-cmd --state 2>/dev/null");
        char *s = chomp_dup(out); g_free(out);
        gboolean run = g_str_equal(s, "running");
        r->firewall_active = run;
        add_finding(r, "Firewall", run ? "firewalld is running"
                                        : "firewalld not running",
                    run ? SEV_OK : SEV_HIGH,
                    run ? "firewalld reports running." : "firewalld is installed but not running.",
                    run ? "" : "Start and enable firewalld.",
                    run ? NULL : "sudo systemctl enable --now firewalld");
        g_free(s);
    } else {
        add_finding(r, "Firewall", "No host firewall detected", SEV_MEDIUM,
                    "Neither ufw nor firewalld is installed.",
                    "Install a host firewall and enable a default-deny policy.",
                    "sudo apt-get install -y ufw && sudo ufw enable");
    }
}

/* TRUE if a "addr:port" local endpoint is bound to a wildcard (all-interface)
 * address rather than a specific IP or loopback. */
static gboolean endpoint_is_public(const char *local) {
    return g_str_has_prefix(local, "0.0.0.0:") ||
           g_str_has_prefix(local, "*:")       ||
           g_str_has_prefix(local, "[::]:")    ||
           g_str_has_prefix(local, ":::");
}

/* Parse `ss -tulpn` and report publicly-bound endpoints. TCP listeners are
 * treated as genuine exposed services (more serious); UDP sockets are usually
 * a client/browser side-effect (QUIC/HTTP-3, WebRTC, mDNS) so they are noted
 * far more gently. An active host firewall reduces the severity of TCP cases. */
static void check_listening_ports(ScanReport *r) {
    if (!have_cmd("ss")) return;
    char *out = run_cmd("ss -tulpnH 2>/dev/null");
    if (!out) return;
    char **lines = g_strsplit(out, "\n", -1);
    g_free(out);

    GString *tcp_pub = g_string_new(NULL);
    GString *udp_pub = g_string_new(NULL);
    int tcp_count = 0, udp_count = 0;

    for (int i = 0; lines[i]; i++) {
        if (!*lines[i]) continue;
        /* Columns: Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process */
        char **col = g_strsplit_set(lines[i], " \t", -1);
        char *tok[16]; int n = 0;
        for (int j = 0; col[j] && n < 16; j++)
            if (*col[j]) tok[n++] = col[j];
        if (n >= 5) {
            const char *netid = tok[0];
            const char *local = tok[4];
            /* Process column only present when we have privilege; guard it. */
            const char *proc  = (n >= 7) ? tok[n-1] : "(process hidden — run as root)";
            if (endpoint_is_public(local)) {
                gboolean is_tcp = g_str_has_prefix(netid, "tcp");
                char *line = g_strdup_printf("  %-4s %-24s %s\n",
                                             netid, local, proc);
                if (is_tcp) { g_string_append(tcp_pub, line); tcp_count++; }
                else        { g_string_append(udp_pub, line); udp_count++; }
                g_free(line);
            }
        }
        g_strfreev(col);
    }
    g_strfreev(lines);

    if (tcp_count == 0 && udp_count == 0) {
        add_finding(r, "Network", "No services bound to public interfaces",
                    SEV_OK, "All listening sockets are bound to localhost "
                    "(127.0.0.1 / ::1) or a specific interface.", "", NULL);
    }

    /* --- TCP listeners: the ones that actually matter --- */
    if (tcp_count > 0) {
        Severity sev = r->firewall_active ? SEV_MEDIUM : SEV_HIGH;
        char d[2048];
        g_snprintf(d, sizeof d,
                   "%d TCP service(s) are LISTENING on all interfaces "
                   "(0.0.0.0 / ::), i.e. reachable from other machines%s:\n%s",
                   tcp_count,
                   r->firewall_active ? " (a host firewall is active, which "
                   "limits who can reach them)" : "",
                   tcp_pub->str);
        add_finding(r, "Network", "TCP services exposed on all interfaces",
                    sev, d,
                    r->firewall_active
                    ? "These are real network services. Your firewall is "
                      "active, so the immediate risk is reduced, but confirm "
                      "each one is meant to be reachable. If a service only "
                      "needs local access, bind it to 127.0.0.1; otherwise make "
                      "sure it is patched and requires authentication."
                    : "A TCP service bound to 0.0.0.0 accepts connections from "
                      "anywhere that can route to this host. Bind it to "
                      "127.0.0.1 if it only needs to be local, and/or enable a "
                      "firewall. Make sure each exposed service is patched and "
                      "authenticated.",
                    "sudo ss -tlpn   # review each listener, then restrict it "
                    "in the app config or firewall");
    }

    /* --- UDP sockets: almost always benign client-side traffic --- */
    if (udp_count > 0) {
        char d[2048];
        g_snprintf(d, sizeof d,
                   "%d UDP socket(s) are bound to all interfaces "
                   "(0.0.0.0 / ::). NOTE: this is usually NOT a security "
                   "problem — web browsers, media apps and system services open "
                   "outbound UDP ports for QUIC/HTTP-3, WebRTC and mDNS, and the "
                   "port number is random and changes each run:\n%s",
                   udp_count, udp_pub->str);
        add_finding(r, "Network", "UDP sockets bound to all interfaces (usually benign)",
                    SEV_LOW, d,
                    "Unlike TCP, a UDP socket here is normally a client (e.g. a "
                    "browser doing QUIC/HTTP-3 or a video call), not a server "
                    "waiting for inbound connections. Only investigate if you "
                    "recognise a server process you did not intend to expose. "
                    "Closing the application removes the socket.",
                    NULL);
    }

    g_string_free(tcp_pub, TRUE);
    g_string_free(udp_pub, TRUE);
}

static void check_ssh(ScanReport *r) {
    if (!g_file_test("/etc/ssh/sshd_config", G_FILE_TEST_EXISTS)) {
        add_finding(r, "SSH", "OpenSSH server not configured", SEV_OK,
                    "No /etc/ssh/sshd_config present; SSH server likely not "
                    "installed.", "", NULL);
        return;
    }
    char *cfg = run_cmd("sshd -T 2>/dev/null || cat /etc/ssh/sshd_config");
    if (!cfg) return;
    char *low = g_ascii_strdown(cfg, -1);
    g_free(cfg);

    if (g_strstr_len(low, -1, "permitrootlogin yes")) {
        add_finding(r, "SSH", "Root SSH login permitted", SEV_HIGH,
                    "PermitRootLogin is set to yes.",
                    "Disable direct root login over SSH; log in as a normal "
                    "user and escalate with sudo.",
                    "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' "
                    "/etc/ssh/sshd_config && sudo systemctl restart ssh");
    }
    if (g_strstr_len(low, -1, "passwordauthentication yes")) {
        add_finding(r, "SSH", "SSH password authentication enabled", SEV_MEDIUM,
                    "PasswordAuthentication is enabled.",
                    "Prefer key-based authentication and disable passwords to "
                    "defeat brute-force and credential-stuffing.",
                    "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' "
                    "/etc/ssh/sshd_config && sudo systemctl restart ssh");
    }
    g_free(low);
}

static void check_sudoers(ScanReport *r) {
    if (g_access("/etc/sudoers", R_OK) != 0) {
        add_finding(r, "Privileges", "Sudo rule check skipped (needs root)",
                    SEV_LOW, "/etc/sudoers is not readable without root, so "
                    "passwordless-sudo rules could not be checked.",
                    "Re-run Envision as root (via pkexec) for the full check.",
                    NULL);
        return;
    }
    char *out = run_cmd("grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Privileges", "Passwordless sudo (NOPASSWD) configured",
                    SEV_HIGH, s,
                    "A NOPASSWD sudo rule lets this user — and anything running "
                    "as them, including a compromised app — become root without "
                    "re-entering a password. This is sometimes set intentionally "
                    "for convenience on a single-user machine; if so, understand "
                    "that it removes a key barrier to privilege escalation. The "
                    "safer setup is to scope NOPASSWD to a specific command, or "
                    "remove it and accept the occasional password prompt.",
                    "sudo visudo   # remove or narrow the NOPASSWD rule");
    } else {
        add_finding(r, "Privileges", "No passwordless sudo rules", SEV_OK,
                    "No NOPASSWD entries found in sudoers.", "", NULL);
    }
    g_free(s);
}

static void check_accounts(ScanReport *r) {
    /* Non-root UID 0 accounts. */
    char *uid0 = run_cmd("awk -F: '($3==0){print $1}' /etc/passwd | grep -v '^root$'");
    char *u = chomp_dup(uid0); g_free(uid0);
    if (u && *u) {
        add_finding(r, "Accounts", "Extra UID 0 (root-equivalent) account",
                    SEV_CRITICAL, u,
                    "Accounts other than root with UID 0 have full root power. "
                    "Investigate and remove unless intentional.",
                    "sudo passwd -l <user>   # and review /etc/passwd");
    }
    g_free(u);

    /* Empty password fields. Reading /etc/shadow needs root; never shell out to
     * sudo here — in a GUI with no terminal that would hang waiting for input. */
    if (g_access("/etc/shadow", R_OK) != 0) {
        add_finding(r, "Accounts", "Empty-password check skipped (needs root)",
                    SEV_LOW, "/etc/shadow is not readable, so accounts with "
                    "empty passwords could not be checked.",
                    "Re-run Envision as root (via pkexec) for the full account "
                    "audit.", NULL);
    } else {
        char *empty = run_cmd("awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null");
        char *e = chomp_dup(empty); g_free(empty);
        if (e && *e) {
            add_finding(r, "Accounts", "Account(s) with empty password",
                        SEV_CRITICAL, e,
                        "These accounts can be logged into with no password at "
                        "all. Lock the account or set a password immediately.",
                        "sudo passwd -l <user>");
        } else {
            add_finding(r, "Accounts", "No accounts with empty passwords", SEV_OK,
                        "Every account in /etc/shadow has a password set or is "
                        "locked.", "", NULL);
        }
        g_free(e);
    }
}

static void check_world_writable(ScanReport *r) {
    /* World-writable files in sensitive dirs, excluding sticky-bit dirs. */
    char *out = run_cmd("find /etc /usr/bin /usr/sbin /bin /sbin -xdev -type f "
                        "-perm -0002 2>/dev/null | head -20");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Filesystem", "World-writable files in system dirs",
                    SEV_HIGH, s,
                    "Any user can modify these files. Remove the world-writable "
                    "bit.", "sudo chmod o-w <file>");
    } else {
        add_finding(r, "Filesystem", "No world-writable system files", SEV_OK,
                    "No world-writable files found in core system directories.",
                    "", NULL);
    }
    g_free(s);
}

static void check_suid(ScanReport *r) {
    /* Unexpected SUID binaries: report the full list for review. */
    char *out = run_cmd("find / -xdev -perm -4000 -type f 2>/dev/null | head -40");
    char *s = chomp_dup(out); g_free(out);
    int count = 0;
    if (s && *s) for (char *p = s; *p; p++) if (*p == '\n') count++;
    char d[4096];
    g_snprintf(d, sizeof d,
               "%d SUID binaries found (this is informational — a typical "
               "Linux system has 15-30, and most below are standard system "
               "tools like sudo, passwd, mount and su):\n%s",
               s && *s ? count + 1 : 0, s ? s : "");
    add_finding(r, "Filesystem", "SUID binaries inventory (informational)", SEV_LOW, d,
                "SUID binaries run with their owner's privileges (often root). "
                "Having them is normal and expected. Only act if you spot a "
                "binary you do not recognise or that was added by a non-standard "
                "package — those are worth investigating. There is nothing to "
                "fix here by default.",
                "sudo chmod u-s <binary>   # ONLY for an unexpected binary you "
                "have confirmed does not need SUID");
    g_free(s);
}

static void check_kernel_hardening(ScanReport *r) {
    /* "atleast" = TRUE means any value >= want is acceptable (so a stricter
     * setting such as kptr_restrict=2 or rp_filter=2 is not flagged). */
    struct { const char *key; const char *want; gboolean atleast; const char *why; const char *sev_detail; Severity sev; } params[] = {
        { "kernel.randomize_va_space", "2", FALSE,
          "ASLR should be set to 2 (full randomization).", "ASLR", SEV_HIGH },
        { "net.ipv4.conf.all.rp_filter", "1", TRUE,
          "Reverse-path filtering helps block spoofed packets (1=strict, 2=loose).", "rp_filter", SEV_LOW },
        { "net.ipv4.tcp_syncookies", "1", TRUE,
          "SYN cookies mitigate SYN-flood denial of service.", "syncookies", SEV_LOW },
        { "net.ipv4.conf.all.accept_redirects", "0", FALSE,
          "ICMP redirects should not be accepted on a host.", "accept_redirects", SEV_LOW },
        { "kernel.kptr_restrict", "1", TRUE,
          "Restricting kernel pointer exposure hampers exploit development.", "kptr_restrict", SEV_LOW },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(params); i++) {
        char cmd[128];
        g_snprintf(cmd, sizeof cmd, "sysctl -n %s 2>/dev/null", params[i].key);
        char *out = run_cmd(cmd);
        char *v = chomp_dup(out); g_free(out);
        if (!v || !*v) { g_free(v); continue; } /* key not present on this kernel */
        gboolean ok = params[i].atleast ? (atoi(v) >= atoi(params[i].want))
                                         : g_str_equal(v, params[i].want);
        if (!ok) {
            char d[256], fix[256], title[128];
            g_snprintf(title, sizeof title, "Kernel param %s = %s (want %s)",
                       params[i].sev_detail, v, params[i].want);
            g_snprintf(d, sizeof d, "%s is %s; recommended %s. %s",
                       params[i].key, v, params[i].want, params[i].why);
            g_snprintf(fix, sizeof fix,
                       "echo '%s = %s' | sudo tee /etc/sysctl.d/99-envision.conf "
                       "&& sudo sysctl --system", params[i].key, params[i].want);
            add_finding(r, "Kernel", title, params[i].sev, d, params[i].why, fix);
        }
        g_free(v);
    }
}

static void check_disk_encryption(ScanReport *r) {
    char *out = run_cmd("lsblk -o TYPE 2>/dev/null | grep -c crypt");
    int crypt = out ? atoi(out) : 0;
    g_free(out);
    if (crypt > 0) {
        add_finding(r, "Storage", "Disk encryption in use", SEV_OK,
                    "At least one LUKS/crypt device is present.", "", NULL);
    } else {
        add_finding(r, "Storage", "No disk encryption detected", SEV_MEDIUM,
                    "No LUKS/dm-crypt devices were found.",
                    "Full-disk encryption protects data at rest if the machine "
                    "is lost or stolen. It generally must be enabled at install "
                    "time; plan a reinstall or use encrypted home directories.",
                    NULL);
    }
}

static void check_aslr_services(ScanReport *r) {
    /* Failed systemd units can indicate a misconfigured / abandoned service. */
    if (!have_cmd("systemctl")) return;
    char *out = run_cmd("systemctl list-units --failed --no-legend --plain "
                        "2>/dev/null | awk '{print $1}' | grep -v '^$'");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Services", "Failed systemd units", SEV_LOW, s,
                    "Failed units may be misconfigured or abandoned services. "
                    "Review and either fix or disable them.",
                    "systemctl status <unit>");
    }
    g_free(s);
}

static void check_coredumps(ScanReport *r) {
    char *out = run_cmd("sysctl -n fs.suid_dumpable 2>/dev/null");
    char *v = chomp_dup(out); g_free(out);
    if (v && g_str_equal(v, "1")) {
        add_finding(r, "Kernel", "SUID core dumps enabled", SEV_MEDIUM,
                    "fs.suid_dumpable = 1 allows SUID programs to dump core, "
                    "potentially leaking sensitive memory.",
                    "Set fs.suid_dumpable to 0.",
                    "echo 'fs.suid_dumpable = 0' | sudo tee "
                    "/etc/sysctl.d/99-envision-coredump.conf && sudo sysctl --system");
    }
    g_free(v);
}

/* ------------------------------------------------------------------ */
/* Orchestration                                                       */
/* ------------------------------------------------------------------ */

typedef void (*CheckFn)(ScanReport *);

ScanReport *scan_run(ScanProgressFn progress, gpointer user_data) {
    ScanReport *r = g_new0(ScanReport, 1);
    r->items = g_ptr_array_new_with_free_func(finding_free);

    char *h = run_cmd("hostname");           r->hostname  = chomp_dup(h); g_free(h);
    char *o = run_cmd(". /etc/os-release 2>/dev/null; printf '%s' \"$PRETTY_NAME\"");
    r->os_pretty = chomp_dup(o); g_free(o);
    char *k = run_cmd("uname -sr");          r->kernel    = chomp_dup(k); g_free(k);

    time_t now = time(NULL);
    char buf[64];
    strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S %Z", localtime(&now));
    r->scanned_at = g_strdup(buf);

    r->is_root = (geteuid() == 0);
    if (!r->is_root)
        add_finding(r, "General", "Scan running without root privileges",
                    SEV_LOW, "Some checks (shadow passwords, sudoers, a full "
                    "filesystem sweep) need root and were limited or skipped.",
                    "For a complete report, launch Envision via pkexec so it "
                    "runs as root.", NULL);

    struct { const char *name; CheckFn fn; } checks[] = {
        { "Updates",   check_updates },
        { "Firewall",  check_firewall },
        { "Network",   check_listening_ports },
        { "SSH",       check_ssh },
        { "Privileges",check_sudoers },
        { "Accounts",  check_accounts },
        { "Filesystem (world-writable)", check_world_writable },
        { "Filesystem (SUID)", check_suid },
        { "Kernel",    check_kernel_hardening },
        { "Storage",   check_disk_encryption },
        { "Services",  check_aslr_services },
        { "Core dumps",check_coredumps },
    };
    int total = G_N_ELEMENTS(checks);
    for (int i = 0; i < total; i++) {
        if (progress) progress(checks[i].name, (double)i / total, user_data);
        checks[i].fn(r);
    }
    if (progress) progress("Done", 1.0, user_data);
    return r;
}

void scan_report_free(ScanReport *r) {
    if (!r) return;
    g_ptr_array_free(r->items, TRUE);
    g_free(r->hostname);
    g_free(r->os_pretty);
    g_free(r->kernel);
    g_free(r->scanned_at);
    g_free(r);
}
