import re


class AttributeExtractor:
    _PROFILE_HEADERS = {
        "domain": "domain profile settings",
        "private": "private profile settings",
        "public": "public profile settings",
    }
    _STATE_RE = re.compile(r"^\s*State\s+([A-Za-z]+)\s*$", re.IGNORECASE)
    _WSUS_RE = re.compile(r"^\s*WUServer\s+REG_SZ\s+(\S+)", re.IGNORECASE)
    _KB_RE = re.compile(r"\bKB\d{6,8}\b", re.IGNORECASE)
    _TASK_STATUS_RE = re.compile(r"\b(Ready|Running|Disabled|Queued|Unknown)\s*$", re.IGNORECASE)
    _FOLDER_ID_RE = re.compile(r"^\s*Folder Id:\s*(.+)$", re.IGNORECASE)
    _VALUE_RE = re.compile(r"^\s*Value:\s*(.+)$", re.IGNORECASE)
    _SERVICE_NAME_RE = re.compile(r"^\s*ServiceName:\s*(.+)$", re.IGNORECASE)
    _STARTUP_RE = re.compile(r"^\s*Startup:\s*(.+)$", re.IGNORECASE)
    _COMPUTER_SETTING_RE = re.compile(r"^\s*Computer Setting:\s*(.+)$", re.IGNORECASE)
    _NUMBER_RE = re.compile(r"-?\d+")

    _DEFAULT_BUILTIN_ACCOUNTS = {
        "administrator",
        "guest",
        "defaultaccount",
        "wdagutilityaccount",
    }
    _AV_KEYWORDS = (
        "kaspersky endpoint security",
        "trend micro deep security",
        "windows defender",
        "defender for endpoint",
        "mssense.exe",
        "mcafee",
        "symantec",
        "eset",
        "sophos",
        "crowdstrike",
        "sentinelone",
        "avp.exe",
    )
    _AV_MANAGEMENT_KEYWORDS = (
        "security center network agent",
        "apex central",
        "defender for endpoint",
        "epo agent",
        "manageengine uems",
    )

    def extract(self, parsed_logs):
        lines = [entry["raw"] for entry in parsed_logs if entry.get("raw")]
        lower_lines = [line.lower() for line in lines]
        lower_text = "\n".join(lower_lines)
        attributes = []

        self._extract_firewall_controls(lines, lower_lines, attributes)
        self._extract_password_controls(lines, lower_lines, attributes)
        self._extract_access_controls(lines, lower_lines, attributes)
        self._extract_event_log_controls(lines, lower_lines, attributes)
        self._extract_time_sync_controls(lines, lower_lines, attributes)
        self._extract_hardening_controls(lines, lower_lines, lower_text, attributes)
        self._extract_policy_gap_controls(attributes)

        kb_ids = sorted(set(self._KB_RE.findall("\n".join(lines))))
        hotfix_count = len(kb_ids) if lines else None
        self._add_attribute(
            attributes,
            "hotfix_count",
            hotfix_count,
            f"Detected {len(kb_ids)} unique KB IDs" if kb_ids else "No KB IDs found",
        )

        return attributes

    def _extract_firewall_controls(self, lines, lower_lines, attributes):
        profile_states = self._extract_firewall_profile_states(lines, lower_lines)
        for profile in ("domain", "private", "public"):
            state = profile_states.get(profile)
            self._add_attribute(
                attributes,
                f"firewall_{profile}_profile_state",
                state,
                f"{profile.title()} profile state: {state}" if state else "Profile state not found",
            )

        firewall_enabled = None
        if profile_states:
            firewall_enabled = (
                len(profile_states) == 3
                and all(profile_states.get(p) == "ON" for p in ("domain", "private", "public"))
            )
        self._add_attribute(
            attributes,
            "firewall_enabled",
            firewall_enabled,
            f"Firewall states: {profile_states}" if profile_states else "Firewall section not found",
        )

    def _extract_password_controls(self, lines, lower_lines, attributes):
        wsus_url = self._extract_wsus_url(lines)
        has_wsus_section = any("wsus" in line for line in lower_lines)
        wsus_configured = True if wsus_url else (False if has_wsus_section else None)
        self._add_attribute(
            attributes,
            "wsus_configured",
            wsus_configured,
            f"WUServer: {wsus_url}" if wsus_url else "WUServer value not found",
        )

        automatic_update_policy = self._has_folder_id(
            lines, "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\ScheduledInstallTime"
        )
        self._add_attribute(
            attributes,
            "automatic_update_policy_configured",
            automatic_update_policy,
            "WindowsUpdate AU ScheduledInstallTime policy found"
            if automatic_update_policy
            else "WindowsUpdate AU schedule policy not found",
        )

        min_password_length = self._extract_numeric_setting(lines, "Minimum password length", True)
        max_password_age = self._extract_numeric_setting(lines, "Maximum password age (days)", False)
        password_history = self._extract_numeric_setting(
            lines, "Length of password history maintained", True
        )
        lockout_threshold = self._extract_numeric_setting(lines, "Lockout threshold", True)
        lockout_duration = self._extract_numeric_setting(lines, "Lockout duration (minutes)", True)

        self._add_attribute(
            attributes,
            "password_minimum_length",
            min_password_length,
            self._render_numeric_evidence("Minimum password length", min_password_length),
        )
        self._add_attribute(
            attributes,
            "password_maximum_age_days",
            max_password_age,
            self._render_numeric_evidence("Maximum password age", max_password_age),
        )
        self._add_attribute(
            attributes,
            "password_history_size",
            password_history,
            self._render_numeric_evidence("Password history size", password_history),
        )
        self._add_attribute(
            attributes,
            "lockout_threshold",
            lockout_threshold,
            self._render_numeric_evidence("Lockout threshold", lockout_threshold),
        )
        self._add_attribute(
            attributes,
            "lockout_duration_minutes",
            lockout_duration,
            self._render_numeric_evidence("Lockout duration", lockout_duration),
        )

        lockout_policy_enabled = None if lockout_threshold is None else lockout_threshold > 0
        self._add_attribute(
            attributes,
            "account_lockout_policy_configured",
            lockout_policy_enabled,
            "Lockout threshold is configured (>0)"
            if lockout_policy_enabled
            else "Lockout threshold is missing or disabled",
        )

        complexity_setting = self._extract_policy_computer_setting(lines, "PasswordComplexity")
        complexity_enabled = self._parse_enabled_setting(complexity_setting)
        self._add_attribute(
            attributes,
            "password_complexity_enabled",
            complexity_enabled,
            f"PasswordComplexity setting: {complexity_setting}"
            if complexity_setting is not None
            else "PasswordComplexity setting not found",
        )

        user_rights_present = self._has_any_phrase(
            lower_lines, ("[+] kiem tra user rights assignment", "user rights", "user rights assignment")
        )
        security_options_present = self._has_any_phrase(lower_lines, ("security options",))
        self._add_attribute(
            attributes,
            "user_rights_section_present",
            user_rights_present,
            "User rights section found" if user_rights_present else "User rights section not found",
        )
        self._add_attribute(
            attributes,
            "security_options_section_present",
            security_options_present,
            "Security options section found"
            if security_options_present
            else "Security options section not found",
        )

        startup_items = self._extract_startup_items(lines)
        scheduled_task_total, scheduled_task_running = self._extract_scheduled_tasks(lines)
        self._add_attribute(
            attributes,
            "startup_entries_reviewed",
            startup_items is not None,
            f"Startup entries detected: {startup_items}"
            if startup_items is not None
            else "Startup section not found",
        )
        self._add_attribute(
            attributes,
            "scheduled_tasks_reviewed",
            scheduled_task_total is not None,
            f"Scheduled tasks detected: {scheduled_task_total}, running: {scheduled_task_running}"
            if scheduled_task_total is not None
            else "Scheduled task section not found",
        )

        builtin_accounts = self._extract_default_builtin_accounts(lines)
        builtin_hardened = None if builtin_accounts is None else len(builtin_accounts) == 0
        self._add_attribute(
            attributes,
            "default_builtin_accounts_renamed_or_disabled",
            builtin_hardened,
            "No default builtin account names found"
            if builtin_hardened
            else f"Detected default account names: {sorted(builtin_accounts)}"
            if builtin_accounts is not None
            else "User account inventory not found",
        )

    def _extract_access_controls(self, lines, lower_lines, attributes):
        rdp_rule = self._extract_firewall_rule_dict(lines, "RemoteDesktop-UserMode-In-TCP")
        rdp_port = None
        rdp_non_default_port = None
        rdp_network_restriction = None
        if rdp_rule is not None:
            rdp_port = rdp_rule.get("LPORT")
            rdp_non_default_port = rdp_port is not None and rdp_port != "3389"
            rdp_network_restriction = "RA4" in rdp_rule or "RA6" in rdp_rule

        self._add_attribute(
            attributes,
            "rdp_non_default_port",
            rdp_non_default_port,
            f"RDP firewall rule LPort: {rdp_port}" if rdp_port else "RDP firewall rule not found",
        )
        self._add_attribute(
            attributes,
            "rdp_network_restriction",
            rdp_network_restriction,
            "RDP rule has RA4/RA6 network restriction"
            if rdp_network_restriction
            else "RDP rule has no RA4/RA6 network restriction"
            if rdp_network_restriction is not None
            else "RDP rule not found",
        )

        rdp_nla_required = self._extract_rdp_nla(lines)
        self._add_attribute(
            attributes,
            "remote_desktop_nla_required",
            rdp_nla_required,
            "RDP NLA setting detected"
            if rdp_nla_required is not None
            else "RDP NLA setting not found in log",
        )

        rdp_timeout_minutes = self._extract_rdp_timeout_minutes(lines)
        timeout_configured = None if rdp_timeout_minutes is None else rdp_timeout_minutes > 0
        self._add_attribute(
            attributes,
            "remote_desktop_timeout_configured",
            timeout_configured,
            f"RDP timeout detected: {rdp_timeout_minutes} minutes"
            if rdp_timeout_minutes is not None
            else "RDP timeout setting not found in log",
        )

    def _extract_event_log_controls(self, lines, lower_lines, attributes):
        audit_total, audit_enabled = self._extract_audit_policy_stats(lines)
        audit_policy_enabled = None if audit_total is None else audit_enabled > 0
        self._add_attribute(
            attributes,
            "audit_policy_has_enabled_entries",
            audit_policy_enabled,
            f"Audit subcategories: {audit_total}, enabled entries: {audit_enabled}"
            if audit_total is not None
            else "Audit policy section not found",
        )

        channels = self._extract_event_log_channels(lines)
        core_enabled = None
        if channels:
            core_values = []
            for channel in ("system", "application", "security"):
                value = channels.get(channel, {}).get("enabled")
                if value is None:
                    core_values = []
                    break
                core_values.append(value)
            if core_values:
                core_enabled = all(core_values)

        security_log = channels.get("security", {})
        security_max_size = security_log.get("max_size")
        retention = security_log.get("retention")
        auto_backup = security_log.get("auto_backup")
        retention_or_backup = None
        if retention is not None or auto_backup is not None:
            retention_or_backup = bool(retention) or bool(auto_backup)

        self._add_attribute(
            attributes,
            "eventlog_core_channels_enabled",
            core_enabled,
            "System/Application/Security channels all enabled"
            if core_enabled
            else "One or more core event log channels are disabled/missing"
            if core_enabled is not None
            else "Core event log channel settings not found",
        )
        self._add_attribute(
            attributes,
            "eventlog_security_max_size_bytes",
            security_max_size,
            f"Security log maxSize: {security_max_size}"
            if security_max_size is not None
            else "Security log maxSize not found",
        )
        self._add_attribute(
            attributes,
            "eventlog_retention_or_backup_enabled",
            retention_or_backup,
            f"Security log retention={retention}, autoBackup={auto_backup}"
            if retention_or_backup is not None
            else "Security log retention/autoBackup settings not found",
        )

        event_forwarding = self._has_any_phrase(
            lower_lines,
            ("eventforwarder", "windows event forwarding", "forwardedevents"),
        )
        self._add_attribute(
            attributes,
            "event_forwarding_configured",
            event_forwarding,
            "Event forwarding indicators found"
            if event_forwarding
            else "No event forwarding indicator found",
        )

        event_log_readers_group = self._has_any_phrase(lower_lines, ("groupname: event log readers",))
        self._add_attribute(
            attributes,
            "event_log_readers_group_configured",
            event_log_readers_group,
            "Event Log Readers group assignment found"
            if event_log_readers_group
            else "Event Log Readers group assignment not found",
        )

    def _extract_time_sync_controls(self, lines, lower_lines, attributes):
        time_sync = self._extract_time_sync(lines)
        ntp_policy_configured = self._has_folder_id(
            lines, "Software\\Policies\\Microsoft\\W32time\\Parameters\\NtpServer"
        )

        self._add_attribute(
            attributes,
            "time_sync_healthy",
            time_sync["healthy"],
            time_sync["evidence"],
        )
        self._add_attribute(
            attributes,
            "ntp_policy_configured",
            ntp_policy_configured,
            "NTP server policy found"
            if ntp_policy_configured
            else "NTP server policy not found",
        )

        time_policy_ok = None
        if time_sync["healthy"] is not None:
            time_policy_ok = bool(time_sync["healthy"]) and ntp_policy_configured
        self._add_attribute(
            attributes,
            "time_sync_policy_and_status_ok",
            time_policy_ok,
            f"{time_sync['evidence']}; NTP policy configured={ntp_policy_configured}",
        )

    def _extract_hardening_controls(self, lines, lower_lines, lower_text, attributes):
        spooler_startup = self._extract_service_startup(lines, "Spooler")
        spooler_disabled = None
        if spooler_startup is not None:
            spooler_disabled = "disable" in spooler_startup.lower()
        self._add_attribute(
            attributes,
            "print_spooler_disabled",
            spooler_disabled,
            f"Spooler startup: {spooler_startup}"
            if spooler_startup is not None
            else "Spooler startup policy not found",
        )

        w32time_startup = self._extract_service_startup(lines, "W32Time")
        w32time_auto = None
        if w32time_startup is not None:
            w32time_auto = w32time_startup.lower().startswith("automatic")
        self._add_attribute(
            attributes,
            "w32time_service_automatic",
            w32time_auto,
            f"W32Time startup: {w32time_startup}"
            if w32time_startup is not None
            else "W32Time startup policy not found",
        )

        antivirus_installed = self._contains_any_keyword(lower_text, self._AV_KEYWORDS)
        antivirus_management = self._contains_any_keyword(lower_text, self._AV_MANAGEMENT_KEYWORDS)
        self._add_attribute(
            attributes,
            "antivirus_installed",
            antivirus_installed,
            "Detected AV indicators in installed software/process list"
            if antivirus_installed
            else "No known AV indicator detected",
        )
        self._add_attribute(
            attributes,
            "antivirus_central_management",
            antivirus_management,
            "Detected AV central management indicator"
            if antivirus_management
            else "No AV central management indicator detected",
        )

    def _extract_policy_gap_controls(self, attributes):
        self._add_attribute(
            attributes,
            "data_sanitization_policy_defined",
            None,
            "No decommission/sanitization policy evidence found in collected technical logs",
        )
        self._add_attribute(
            attributes,
            "backup_before_decommission_policy_defined",
            None,
            "No backup-before-decommission policy evidence found in collected technical logs",
        )
        self._add_attribute(
            attributes,
            "secure_erase_verification_policy_defined",
            None,
            "No secure erase verification policy evidence found in collected technical logs",
        )
        self._add_attribute(
            attributes,
            "vulnerability_remediation_policy_defined",
            None,
            "No pre-production remediation policy evidence found in collected technical logs",
        )

    def _extract_firewall_profile_states(self, lines, lower_lines):
        states = {}
        for idx, lower_line in enumerate(lower_lines):
            for profile, header in self._PROFILE_HEADERS.items():
                if profile in states or header not in lower_line:
                    continue

                for lookahead in lines[idx : min(idx + 10, len(lines))]:
                    match = self._STATE_RE.match(lookahead)
                    if match:
                        states[profile] = match.group(1).upper()
                        break
        return states

    def _extract_wsus_url(self, lines):
        for line in lines:
            match = self._WSUS_RE.match(line)
            if match:
                return match.group(1)
        return None

    def _extract_numeric_setting(self, lines, label, zero_for_keywords):
        prefix = f"{label.lower()}:"
        for line in lines:
            stripped = line.strip()
            if not stripped.lower().startswith(prefix):
                continue
            value = stripped.split(":", 1)[1].strip()
            return self._parse_numeric_value(value, zero_for_keywords)
        return None

    def _extract_policy_computer_setting(self, lines, policy_name):
        for index, line in enumerate(lines):
            if "policy:" not in line.lower() or policy_name.lower() not in line.lower():
                continue
            for lookahead in lines[index + 1 : min(index + 5, len(lines))]:
                match = self._COMPUTER_SETTING_RE.match(lookahead)
                if match:
                    return match.group(1).strip()
        return None

    def _extract_startup_items(self, lines):
        in_section = False
        in_table = False
        count = 0
        for line in lines:
            stripped = line.strip()
            lower = stripped.lower()
            if "[+] kiem tra start up list" in lower:
                in_section = True
                continue
            if in_section and "[+] kiem tra task schedule" in lower:
                break
            if not in_section:
                continue

            if lower.startswith("caption"):
                in_table = True
                continue
            if in_table:
                if not stripped or stripped.startswith("#-#") or stripped.lower().startswith("hkey_"):
                    in_table = False
                    continue
                count += 1

        return count if in_section else None

    def _extract_scheduled_tasks(self, lines):
        in_section = False
        total = 0
        running = 0
        for line in lines:
            stripped = line.strip()
            lower = stripped.lower()
            if "[+] kiem tra task schedule" in lower:
                in_section = True
                continue
            if in_section and "[+] kiem tra cai dat av" in lower:
                break
            if not in_section:
                continue
            if self._TASK_STATUS_RE.search(stripped):
                total += 1
                if stripped.lower().endswith("running"):
                    running += 1
        if not in_section:
            return None, None
        return total, running

    def _extract_default_builtin_accounts(self, lines):
        in_section = False
        account_tokens = set()
        for line in lines:
            stripped = line.strip()
            lower = stripped.lower()
            if "user accounts for" in lower:
                in_section = True
                continue
            if in_section and "the command completed successfully." in lower:
                break
            if not in_section or not stripped or stripped.startswith("-"):
                continue
            for token in stripped.split():
                account_tokens.add(token.lower())
        if not in_section:
            return None
        return {
            account
            for account in self._DEFAULT_BUILTIN_ACCOUNTS
            if account in account_tokens
        }

    def _extract_firewall_rule_dict(self, lines, folder_fragment):
        for index, line in enumerate(lines):
            folder_match = self._FOLDER_ID_RE.match(line)
            if not folder_match:
                continue
            folder_id = folder_match.group(1)
            if folder_fragment.lower() not in folder_id.lower():
                continue

            if index + 1 >= len(lines):
                return {}
            value_match = self._VALUE_RE.match(lines[index + 1])
            if not value_match:
                return {}
            decoded = self._decode_registry_value_bytes(value_match.group(1))
            return self._parse_firewall_rule(decoded)
        return None

    def _extract_audit_policy_stats(self, lines):
        in_section = False
        total = 0
        enabled = 0
        for line in lines:
            stripped = line.strip()
            lower = stripped.lower()
            if "[+] list audit policy" in lower:
                in_section = True
                continue
            if in_section and "iii.kiem tra cau hinh thiet bi" in lower:
                break
            if not in_section:
                continue

            status = None
            if stripped.endswith("No Auditing"):
                status = "no"
            elif stripped.endswith("Success and Failure"):
                status = "enabled"
            elif stripped.endswith("Success"):
                status = "enabled"
            elif stripped.endswith("Failure"):
                status = "enabled"
            if status is None:
                continue
            total += 1
            if status == "enabled":
                enabled += 1

        if not in_section:
            return None, None
        return total, enabled

    def _extract_event_log_channels(self, lines):
        channels = {}
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped.lower().startswith("name:"):
                continue
            channel = stripped.split(":", 1)[1].strip().lower()
            if channel not in {"system", "application", "security"}:
                continue

            settings = channels.setdefault(channel, {})
            for lookahead in lines[index + 1 : min(index + 25, len(lines))]:
                entry = lookahead.strip()
                entry_lower = entry.lower()
                if entry_lower.startswith("name:"):
                    break
                if entry_lower.startswith("enabled:"):
                    settings["enabled"] = self._parse_bool(entry.split(":", 1)[1].strip())
                elif entry_lower.startswith("retention:"):
                    settings["retention"] = self._parse_bool(entry.split(":", 1)[1].strip())
                elif entry_lower.startswith("autobackup:"):
                    settings["auto_backup"] = self._parse_bool(entry.split(":", 1)[1].strip())
                elif entry_lower.startswith("maxsize:"):
                    settings["max_size"] = self._parse_numeric_value(
                        entry.split(":", 1)[1].strip(), False
                    )
        return channels

    def _extract_time_sync(self, lines):
        leap_indicator = None
        source = None
        for line in lines:
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("leap indicator:"):
                leap_indicator = stripped.split(":", 1)[1].strip()
            elif lower.startswith("source:"):
                source = stripped.split(":", 1)[1].strip()

        if leap_indicator is None and source is None:
            return {"healthy": None, "evidence": "Time synchronization section not found"}

        not_synchronized = False
        if leap_indicator and "not synchronized" in leap_indicator.lower():
            not_synchronized = True
        if source and source.lower() in {"free-running system clock", "local cmos clock"}:
            not_synchronized = True
        if leap_indicator and leap_indicator.lower().startswith("3("):
            not_synchronized = True

        evidence = f"Leap Indicator={leap_indicator}; Source={source}"
        return {"healthy": not not_synchronized, "evidence": evidence}

    def _extract_service_startup(self, lines, service_name):
        for index, line in enumerate(lines):
            service_match = self._SERVICE_NAME_RE.match(line)
            if not service_match:
                continue
            if service_match.group(1).strip().lower() != service_name.lower():
                continue
            for lookahead in lines[index + 1 : min(index + 4, len(lines))]:
                startup_match = self._STARTUP_RE.match(lookahead)
                if startup_match:
                    return startup_match.group(1).strip()
        return None

    def _extract_rdp_nla(self, lines):
        for line in lines:
            lower = line.lower()
            if "userauthentication" not in lower and "network level authentication" not in lower:
                continue
            numbers = self._NUMBER_RE.findall(line)
            if numbers:
                return int(numbers[-1]) == 1
            if "enabled" in lower:
                return True
            if "disabled" in lower:
                return False
        return None

    def _extract_rdp_timeout_minutes(self, lines):
        timeout_keywords = ("maxidletime", "maxdisconnectiontime", "maxconnectiontime", "idle timeout")
        for line in lines:
            lower = line.lower()
            if not any(keyword in lower for keyword in timeout_keywords):
                continue
            values = self._NUMBER_RE.findall(line)
            if values:
                raw_value = int(values[-1])
                return raw_value // 60000 if raw_value > 10000 else raw_value
        return None

    def _has_folder_id(self, lines, folder_id_fragment):
        for line in lines:
            match = self._FOLDER_ID_RE.match(line)
            if not match:
                continue
            folder_id = match.group(1)
            if folder_id_fragment.lower() in folder_id.lower():
                return True
        return False

    @staticmethod
    def _parse_numeric_value(raw_value, zero_for_keywords):
        value = raw_value.strip()
        if not value:
            return None

        lowered = value.lower()
        if zero_for_keywords and lowered in {"never", "none", "disabled"}:
            return 0

        match = re.search(r"-?\d+", value)
        if not match:
            return None
        return int(match.group())

    @staticmethod
    def _parse_enabled_setting(setting):
        if setting is None:
            return None
        lowered = setting.strip().lower()
        if lowered in {"enabled", "true"}:
            return True
        if lowered in {"not enabled", "disabled", "false"}:
            return False
        return None

    @staticmethod
    def _parse_bool(value):
        lowered = value.strip().lower()
        if lowered in {"true", "enabled", "yes"}:
            return True
        if lowered in {"false", "disabled", "no"}:
            return False
        return None

    @staticmethod
    def _decode_registry_value_bytes(value_string):
        parts = [part.strip() for part in value_string.split(",")]
        numbers = []
        for part in parts:
            if part.isdigit():
                numbers.append(int(part))
        if not numbers:
            return ""
        try:
            return bytes(numbers).decode("utf-16-le", errors="ignore").rstrip("\x00")
        except ValueError:
            return ""

    @staticmethod
    def _parse_firewall_rule(decoded_rule):
        rule = {}
        for item in decoded_rule.split("|"):
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            rule[key.strip().upper()] = value.strip()
        return rule

    @staticmethod
    def _has_any_phrase(lower_lines, phrases):
        for line in lower_lines:
            for phrase in phrases:
                if phrase in line:
                    return True
        return False

    @staticmethod
    def _contains_any_keyword(lower_text, keywords):
        return any(keyword in lower_text for keyword in keywords)

    @staticmethod
    def _render_numeric_evidence(label, value):
        return f"{label}: {value}" if value is not None else f"{label} not found or non-numeric"

    @staticmethod
    def _add_attribute(attributes, attribute, value, evidence):
        attributes.append({"attribute": attribute, "value": value, "evidence": evidence})
