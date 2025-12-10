// SQL_HACK3R - Complete Game Application
// Single file bundle for compatibility

// ============================================================
// DATABASE - Fake Database Engine
// ============================================================

const GameDatabase = {
    // SQL/PostgreSQL Tables
    sql: {
        users: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'username', type: 'VARCHAR(50)' },
                { name: 'email', type: 'VARCHAR(100)' },
                { name: 'password_hash', type: 'VARCHAR(255)' },
                { name: 'role', type: 'VARCHAR(20)' },
                { name: 'created_at', type: 'TIMESTAMP' },
                { name: 'last_login', type: 'TIMESTAMP' },
                { name: 'status', type: 'VARCHAR(20)' }
            ],
            data: [
                { id: 1, username: 'admin', email: 'admin@corpsec.net', password_hash: '$2b$12$LQv3c1yqBw...', role: 'administrator', created_at: '2024-01-15 08:30:00', last_login: '2024-12-01 14:22:00', status: 'active' },
                { id: 2, username: 'jsmith', email: 'j.smith@corpsec.net', password_hash: '$2b$12$9Xk2mPq...', role: 'analyst', created_at: '2024-02-20 10:15:00', last_login: '2024-11-28 09:45:00', status: 'active' },
                { id: 3, username: 'mchen', email: 'm.chen@corpsec.net', password_hash: '$2b$12$Hj7nKlm...', role: 'developer', created_at: '2024-03-10 14:00:00', last_login: '2024-11-30 16:30:00', status: 'active' },
                { id: 4, username: 'ghost_user', email: 'shadow@darknet.onion', password_hash: '$2b$12$ZzTop...', role: 'unknown', created_at: '2024-06-01 00:00:00', last_login: '2024-12-01 03:33:33', status: 'suspicious' },
                { id: 5, username: 'sarah_ops', email: 's.operations@corpsec.net', password_hash: '$2b$12$Mnb8x...', role: 'operations', created_at: '2024-04-05 09:00:00', last_login: '2024-11-29 11:20:00', status: 'active' },
                { id: 6, username: 'backup_sys', email: 'backup@internal.corpsec.net', password_hash: '$2b$12$Backup...', role: 'system', created_at: '2024-01-01 00:00:00', last_login: '2024-12-01 04:00:00', status: 'active' },
                { id: 7, username: 'temp_contractor', email: 'contractor@external.com', password_hash: '$2b$12$Temp123...', role: 'contractor', created_at: '2024-10-01 08:00:00', last_login: '2024-10-15 17:00:00', status: 'disabled' }
            ]
        },

        access_logs: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'user_id', type: 'INT', key: 'FK' },
                { name: 'action', type: 'VARCHAR(50)' },
                { name: 'resource', type: 'VARCHAR(100)' },
                { name: 'ip_address', type: 'VARCHAR(45)' },
                { name: 'timestamp', type: 'TIMESTAMP' },
                { name: 'success', type: 'BOOLEAN' }
            ],
            data: [
                { id: 1, user_id: 1, action: 'LOGIN', resource: '/admin/dashboard', ip_address: '192.168.1.100', timestamp: '2024-12-01 14:22:00', success: true },
                { id: 2, user_id: 4, action: 'LOGIN', resource: '/admin/dashboard', ip_address: '10.0.0.99', timestamp: '2024-12-01 03:33:33', success: true },
                { id: 3, user_id: 4, action: 'DOWNLOAD', resource: '/secrets/classified.zip', ip_address: '10.0.0.99', timestamp: '2024-12-01 03:35:00', success: true },
                { id: 4, user_id: 2, action: 'VIEW', resource: '/reports/quarterly', ip_address: '192.168.1.45', timestamp: '2024-11-28 09:50:00', success: true },
                { id: 5, user_id: 4, action: 'DELETE', resource: '/logs/audit_trail', ip_address: '10.0.0.99', timestamp: '2024-12-01 03:40:00', success: false },
                { id: 6, user_id: 3, action: 'COMMIT', resource: '/repos/main-app', ip_address: '192.168.1.78', timestamp: '2024-11-30 16:35:00', success: true },
                { id: 7, user_id: 1, action: 'CONFIG_CHANGE', resource: '/system/firewall', ip_address: '192.168.1.100', timestamp: '2024-12-01 14:30:00', success: true },
                { id: 8, user_id: 4, action: 'UPLOAD', resource: '/tmp/backdoor.sh', ip_address: '10.0.0.99', timestamp: '2024-12-01 03:45:00', success: true },
                { id: 9, user_id: 6, action: 'BACKUP', resource: '/data/full_backup', ip_address: '127.0.0.1', timestamp: '2024-12-01 04:00:00', success: true },
                { id: 10, user_id: 4, action: 'LOGIN', resource: '/admin/dashboard', ip_address: '185.234.72.19', timestamp: '2024-12-01 03:30:00', success: true }
            ]
        },

        servers: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'hostname', type: 'VARCHAR(50)' },
                { name: 'ip_address', type: 'VARCHAR(45)' },
                { name: 'location', type: 'VARCHAR(50)' },
                { name: 'status', type: 'VARCHAR(20)' },
                { name: 'os', type: 'VARCHAR(50)' },
                { name: 'last_patch', type: 'DATE' },
                { name: 'classification', type: 'VARCHAR(20)' }
            ],
            data: [
                { id: 1, hostname: 'web-prod-01', ip_address: '10.0.1.10', location: 'DC-EAST', status: 'online', os: 'Ubuntu 22.04', last_patch: '2024-11-15', classification: 'public' },
                { id: 2, hostname: 'db-master', ip_address: '10.0.2.20', location: 'DC-EAST', status: 'online', os: 'RHEL 8', last_patch: '2024-11-20', classification: 'internal' },
                { id: 3, hostname: 'secret-vault', ip_address: '10.0.99.1', location: 'DC-CLASSIFIED', status: 'online', os: 'Custom Hardened', last_patch: '2024-12-01', classification: 'top_secret' },
                { id: 4, hostname: 'dev-server', ip_address: '10.0.3.30', location: 'DC-WEST', status: 'online', os: 'Debian 12', last_patch: '2024-10-01', classification: 'internal' },
                { id: 5, hostname: 'legacy-app', ip_address: '10.0.4.40', location: 'DC-WEST', status: 'degraded', os: 'Windows Server 2012', last_patch: '2023-06-15', classification: 'internal' },
                { id: 6, hostname: 'honeypot-01', ip_address: '10.0.0.99', location: 'DMZ', status: 'online', os: 'Custom Decoy', last_patch: '2024-11-30', classification: 'decoy' }
            ]
        },

        credentials: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'service_name', type: 'VARCHAR(50)' },
                { name: 'username', type: 'VARCHAR(50)' },
                { name: 'encrypted_password', type: 'VARCHAR(255)' },
                { name: 'server_id', type: 'INT', key: 'FK' },
                { name: 'created_by', type: 'INT', key: 'FK' },
                { name: 'access_level', type: 'INT' }
            ],
            data: [
                { id: 1, service_name: 'MySQL', username: 'root', encrypted_password: 'enc:AES256:Kj8mNpQ2...', server_id: 2, created_by: 1, access_level: 10 },
                { id: 2, service_name: 'SSH', username: 'deploy', encrypted_password: 'enc:AES256:Xm4nBvC1...', server_id: 1, created_by: 1, access_level: 5 },
                { id: 3, service_name: 'VaultAPI', username: 'vault_admin', encrypted_password: 'enc:AES256:Zt9pLkM3...FLAG{SQL_MASTER}', server_id: 3, created_by: 1, access_level: 10 },
                { id: 4, service_name: 'Jenkins', username: 'ci_user', encrypted_password: 'enc:AES256:Qw2eRtY7...', server_id: 4, created_by: 3, access_level: 3 },
                { id: 5, service_name: 'FTP', username: 'backup_ftp', encrypted_password: 'enc:AES256:Hy6uJkI8...', server_id: 5, created_by: 6, access_level: 2 }
            ]
        },

        transactions: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'account_from', type: 'VARCHAR(20)' },
                { name: 'account_to', type: 'VARCHAR(20)' },
                { name: 'amount', type: 'DECIMAL(15,2)' },
                { name: 'currency', type: 'VARCHAR(3)' },
                { name: 'timestamp', type: 'TIMESTAMP' },
                { name: 'status', type: 'VARCHAR(20)' },
                { name: 'memo', type: 'VARCHAR(255)' }
            ],
            data: [
                { id: 1, account_from: 'ACC-001-CORP', account_to: 'ACC-999-OFFSHORE', amount: 50000.00, currency: 'USD', timestamp: '2024-11-15 02:30:00', status: 'completed', memo: 'Consulting fees' },
                { id: 2, account_from: 'ACC-002-OPS', account_to: 'ACC-003-VENDOR', amount: 12500.00, currency: 'USD', timestamp: '2024-11-20 10:00:00', status: 'completed', memo: 'Equipment purchase' },
                { id: 3, account_from: 'ACC-001-CORP', account_to: 'ACC-888-SHELL', amount: 175000.00, currency: 'USD', timestamp: '2024-11-25 03:15:00', status: 'completed', memo: 'Project Phoenix' },
                { id: 4, account_from: 'ACC-888-SHELL', account_to: 'ACC-777-CAYMAN', amount: 174500.00, currency: 'USD', timestamp: '2024-11-25 03:20:00', status: 'completed', memo: 'Transfer' },
                { id: 5, account_from: 'ACC-002-OPS', account_to: 'ACC-004-PAYROLL', amount: 85000.00, currency: 'USD', timestamp: '2024-11-30 09:00:00', status: 'completed', memo: 'November payroll' },
                { id: 6, account_from: 'ACC-777-CAYMAN', account_to: 'BTC-WALLET-X9K2M', amount: 174000.00, currency: 'USD', timestamp: '2024-11-26 01:00:00', status: 'completed', memo: 'Crypto conversion' }
            ]
        },

        employees: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'employee_id', type: 'VARCHAR(10)' },
                { name: 'first_name', type: 'VARCHAR(50)' },
                { name: 'last_name', type: 'VARCHAR(50)' },
                { name: 'department', type: 'VARCHAR(50)' },
                { name: 'salary', type: 'DECIMAL(10,2)' },
                { name: 'manager_id', type: 'INT', key: 'FK' },
                { name: 'hire_date', type: 'DATE' },
                { name: 'clearance_level', type: 'INT' }
            ],
            data: [
                { id: 1, employee_id: 'EMP-001', first_name: 'Richard', last_name: 'Sterling', department: 'Executive', salary: 450000.00, manager_id: null, hire_date: '2015-01-01', clearance_level: 10 },
                { id: 2, employee_id: 'EMP-002', first_name: 'Sarah', last_name: 'Chen', department: 'Operations', salary: 125000.00, manager_id: 1, hire_date: '2018-03-15', clearance_level: 7 },
                { id: 3, employee_id: 'EMP-003', first_name: 'Marcus', last_name: 'Webb', department: 'IT Security', salary: 145000.00, manager_id: 1, hire_date: '2017-06-01', clearance_level: 8 },
                { id: 4, employee_id: 'EMP-004', first_name: 'Lisa', last_name: 'Park', department: 'Finance', salary: 95000.00, manager_id: 2, hire_date: '2020-01-10', clearance_level: 5 },
                { id: 5, employee_id: 'EMP-005', first_name: 'James', last_name: 'Morrison', department: 'IT Security', salary: 110000.00, manager_id: 3, hire_date: '2021-04-20', clearance_level: 6 },
                { id: 6, employee_id: 'EMP-006', first_name: 'Elena', last_name: 'Volkov', department: 'Research', salary: 135000.00, manager_id: 1, hire_date: '2019-08-01', clearance_level: 9 },
                { id: 7, employee_id: 'EMP-007', first_name: 'David', last_name: 'Kim', department: 'Development', salary: 105000.00, manager_id: 3, hire_date: '2022-02-14', clearance_level: 4 }
            ]
        },

        secret_projects: {
            columns: [
                { name: 'id', type: 'INT', key: 'PK' },
                { name: 'codename', type: 'VARCHAR(50)' },
                { name: 'description', type: 'TEXT' },
                { name: 'lead_id', type: 'INT', key: 'FK' },
                { name: 'budget', type: 'DECIMAL(15,2)' },
                { name: 'status', type: 'VARCHAR(20)' },
                { name: 'classification', type: 'VARCHAR(20)' },
                { name: 'target_date', type: 'DATE' }
            ],
            data: [
                { id: 1, codename: 'PHOENIX', description: 'Advanced AI surveillance system', lead_id: 6, budget: 2500000.00, status: 'active', classification: 'top_secret', target_date: '2025-06-01' },
                { id: 2, codename: 'NIGHTSHADE', description: 'Quantum encryption breakthrough', lead_id: 3, budget: 5000000.00, status: 'active', classification: 'top_secret', target_date: '2025-12-01' },
                { id: 3, codename: 'ECHO', description: 'Social media analysis platform', lead_id: 2, budget: 800000.00, status: 'completed', classification: 'secret', target_date: '2024-09-01' },
                { id: 4, codename: 'SPECTER', description: 'Zero-day exploit repository', lead_id: 3, budget: 1500000.00, status: 'active', classification: 'top_secret', target_date: '2025-03-01' }
            ]
        }
    },

    // PostgreSQL specific tables
    postgresql: {
        network_scans: {
            columns: [
                { name: 'id', type: 'SERIAL', key: 'PK' },
                { name: 'target_ip', type: 'INET' },
                { name: 'open_ports', type: 'INTEGER[]' },
                { name: 'services', type: 'JSONB' },
                { name: 'vulnerabilities', type: 'TEXT[]' },
                { name: 'scan_time', type: 'TIMESTAMP' },
                { name: 'risk_score', type: 'NUMERIC(3,1)' }
            ],
            data: [
                { id: 1, target_ip: '10.0.1.10', open_ports: [22, 80, 443], services: { ssh: '8.2p1', nginx: '1.18.0', ssl: 'TLS1.3' }, vulnerabilities: ['CVE-2024-1234'], scan_time: '2024-12-01 10:00:00', risk_score: 3.5 },
                { id: 2, target_ip: '10.0.2.20', open_ports: [22, 3306, 5432], services: { ssh: '8.4p1', mysql: '8.0.35', postgresql: '15.4' }, vulnerabilities: [], scan_time: '2024-12-01 10:05:00', risk_score: 2.0 },
                { id: 3, target_ip: '10.0.99.1', open_ports: [22, 443, 8443], services: { ssh: '9.0p1', vault: '1.15.0', custom: 'unknown' }, vulnerabilities: [], scan_time: '2024-12-01 10:10:00', risk_score: 1.0 },
                { id: 4, target_ip: '10.0.4.40', open_ports: [22, 80, 443, 3389, 445, 139], services: { ssh: '7.9p1', iis: '8.5', rdp: '10.0', smb: '2.0' }, vulnerabilities: ['CVE-2023-5678', 'CVE-2022-9999', 'MS17-010'], scan_time: '2024-12-01 10:15:00', risk_score: 9.8 },
                { id: 5, target_ip: '10.0.0.99', open_ports: [21, 22, 23, 80, 443, 3306, 8080], services: { ftp: '3.0.3', ssh: '7.4p1', telnet: 'active', http: 'Apache 2.2', mysql: '5.5.62' }, vulnerabilities: ['CVE-2021-1111', 'CVE-2020-2222', 'BACKDOOR-DETECTED'], scan_time: '2024-12-01 10:20:00', risk_score: 10.0 }
            ]
        },

        threat_intel: {
            columns: [
                { name: 'id', type: 'SERIAL', key: 'PK' },
                { name: 'indicator', type: 'TEXT' },
                { name: 'indicator_type', type: 'VARCHAR(20)' },
                { name: 'threat_actor', type: 'VARCHAR(50)' },
                { name: 'metadata', type: 'JSONB' },
                { name: 'tags', type: 'TEXT[]' },
                { name: 'first_seen', type: 'TIMESTAMP' },
                { name: 'confidence', type: 'INTEGER' }
            ],
            data: [
                { id: 1, indicator: '185.234.72.19', indicator_type: 'ip', threat_actor: 'APT-SHADOW', metadata: { country: 'RU', asn: 'AS12345', reputation: 'malicious' }, tags: ['apt', 'ransomware', 'c2'], first_seen: '2024-06-15 00:00:00', confidence: 95 },
                { id: 2, indicator: 'evil-domain.tk', indicator_type: 'domain', threat_actor: 'APT-SHADOW', metadata: { registrar: 'anonymous', created: '2024-05-01' }, tags: ['phishing', 'malware-distribution'], first_seen: '2024-05-10 00:00:00', confidence: 90 },
                { id: 3, indicator: 'a1b2c3d4e5f6...', indicator_type: 'hash', threat_actor: 'CRYPTOLOCKER-X', metadata: { malware_family: 'ransomware', file_type: 'exe' }, tags: ['ransomware', 'encryption'], first_seen: '2024-08-20 00:00:00', confidence: 99 },
                { id: 4, indicator: 'shadow@darknet.onion', indicator_type: 'email', threat_actor: 'APT-SHADOW', metadata: { associated_campaigns: ['PHOENIX-BREACH', 'DATA-HEIST-2024'] }, tags: ['apt', 'insider-threat'], first_seen: '2024-06-01 00:00:00', confidence: 85 },
                { id: 5, indicator: 'BTC-WALLET-X9K2M', indicator_type: 'crypto', threat_actor: 'MONEY-MULE-NET', metadata: { total_received: '45.5 BTC', linked_ransomware: true }, tags: ['financial', 'laundering'], first_seen: '2024-09-01 00:00:00', confidence: 88 }
            ]
        },

        audit_events: {
            columns: [
                { name: 'id', type: 'BIGSERIAL', key: 'PK' },
                { name: 'event_time', type: 'TIMESTAMPTZ' },
                { name: 'actor', type: 'VARCHAR(100)' },
                { name: 'action', type: 'VARCHAR(50)' },
                { name: 'target', type: 'VARCHAR(200)' },
                { name: 'details', type: 'JSONB' },
                { name: 'source_ip', type: 'INET' },
                { name: 'geo_location', type: 'POINT' }
            ],
            data: [
                { id: 1, event_time: '2024-12-01 03:30:00+00', actor: 'ghost_user', action: 'authentication', target: 'admin_portal', details: { method: 'password', mfa_bypassed: true, session_id: 'xyz789' }, source_ip: '185.234.72.19', geo_location: '(55.7558, 37.6173)' },
                { id: 2, event_time: '2024-12-01 03:33:33+00', actor: 'ghost_user', action: 'privilege_escalation', target: 'root_access', details: { original_role: 'guest', new_role: 'administrator', exploit: 'CVE-2024-0001' }, source_ip: '185.234.72.19', geo_location: '(55.7558, 37.6173)' },
                { id: 3, event_time: '2024-12-01 03:35:00+00', actor: 'ghost_user', action: 'data_exfiltration', target: '/secrets/classified.zip', details: { file_size: '2.5GB', encryption: 'none', destination: 'external' }, source_ip: '185.234.72.19', geo_location: '(55.7558, 37.6173)' },
                { id: 4, event_time: '2024-12-01 03:40:00+00', actor: 'ghost_user', action: 'log_tampering', target: '/var/log/audit.log', details: { lines_deleted: 150, time_range: '2024-11-01 to 2024-11-30' }, source_ip: '185.234.72.19', geo_location: '(55.7558, 37.6173)' },
                { id: 5, event_time: '2024-12-01 03:45:00+00', actor: 'ghost_user', action: 'backdoor_install', target: '/tmp/backdoor.sh', details: { persistence: 'cron', callback: '185.234.72.19:4444', encrypted: true }, source_ip: '185.234.72.19', geo_location: '(55.7558, 37.6173)' }
            ]
        }
    },

    // NoSQL/MongoDB Collections
    nosql: {
        agents: {
            data: [
                { _id: 'agent_001', codename: 'VIPER', real_name: 'CLASSIFIED', status: 'active', handler: 'agent_005', specialization: ['infiltration', 'social_engineering'], missions_completed: 47, current_location: { city: 'Berlin', country: 'Germany', coordinates: [52.52, 13.405] }, equipment: ['encrypted_phone', 'lockpicks', 'usb_implant'], last_contact: '2024-12-01T08:00:00Z' },
                { _id: 'agent_002', codename: 'GHOST', real_name: 'CLASSIFIED', status: 'active', handler: 'agent_005', specialization: ['cyber_ops', 'zero_day_exploitation'], missions_completed: 63, current_location: { city: 'Tokyo', country: 'Japan', coordinates: [35.6762, 139.6503] }, equipment: ['custom_laptop', 'rf_scanner', 'hardware_implants'], last_contact: '2024-12-01T06:30:00Z' },
                { _id: 'agent_003', codename: 'PHOENIX', real_name: 'CLASSIFIED', status: 'compromised', handler: 'agent_005', specialization: ['surveillance', 'counter_intelligence'], missions_completed: 31, current_location: { city: 'Unknown', country: 'Unknown', coordinates: [0, 0] }, equipment: [], last_contact: '2024-11-15T23:59:59Z', notes: 'Last seen in Moscow. Presumed captured.' },
                { _id: 'agent_004', codename: 'SPECTER', real_name: 'CLASSIFIED', status: 'active', handler: 'agent_005', specialization: ['assassination', 'extraction'], missions_completed: 89, current_location: { city: 'London', country: 'UK', coordinates: [51.5074, -0.1278] }, equipment: ['suppressed_pistol', 'tactical_gear', 'fake_passports'], last_contact: '2024-12-01T12:00:00Z' },
                { _id: 'agent_005', codename: 'ORACLE', real_name: 'CLASSIFIED', status: 'active', handler: null, specialization: ['coordination', 'intelligence_analysis'], missions_completed: 156, current_location: { city: 'Langley', country: 'USA', coordinates: [38.9517, -77.1467] }, equipment: ['secure_terminal', 'satellite_uplink'], last_contact: '2024-12-01T14:00:00Z', clearance: 'ULTRA' }
            ]
        },

        missions: {
            data: [
                { _id: 'mission_101', codename: 'DARK_HARVEST', status: 'completed', assigned_agents: ['agent_001', 'agent_002'], objective: 'Extract financial data from target corporation', target: { name: 'MegaCorp Industries', location: 'Frankfurt', sector: 'Finance' }, timeline: { start: '2024-10-01', end: '2024-10-15' }, outcome: 'success', intel_gathered: ['transaction_logs', 'employee_database', 'encryption_keys'], casualties: 0 },
                { _id: 'mission_102', codename: 'SHADOW_STRIKE', status: 'active', assigned_agents: ['agent_004'], objective: 'Neutralize double agent', target: { name: 'REDACTED', location: 'Vienna', affiliation: 'Enemy_State' }, timeline: { start: '2024-11-20', end: null }, outcome: null, intel_gathered: [], casualties: null },
                { _id: 'mission_103', codename: 'SILENT_THUNDER', status: 'failed', assigned_agents: ['agent_003'], objective: 'Plant surveillance devices in embassy', target: { name: 'Foreign Embassy', location: 'Moscow', country: 'Russia' }, timeline: { start: '2024-11-01', end: '2024-11-15' }, outcome: 'agent_compromised', intel_gathered: ['partial_blueprints'], casualties: 1, notes: 'Agent PHOENIX captured. Mission abort.' },
                { _id: 'mission_104', codename: 'CYBER_STORM', status: 'planning', assigned_agents: ['agent_002'], objective: 'Infiltrate enemy cyber command', target: { name: 'State Cyber Unit', location: 'Classified', infrastructure: 'critical' }, timeline: { start: '2025-01-15', end: null }, outcome: null, required_intel: ['network_topology', 'access_credentials', 'physical_security'], budget: 2500000 },
                { _id: 'mission_105', codename: 'IRON_CURTAIN', status: 'completed', assigned_agents: ['agent_001', 'agent_004'], objective: 'Extract defector with critical intelligence', target: { name: 'Dr. Alexei Volkov', location: 'Prague', value: 'high' }, timeline: { start: '2024-09-01', end: '2024-09-10' }, outcome: 'success', intel_gathered: ['weapons_program_details', 'sleeper_agent_list', 'FLAG{NOSQL_NINJA}'], casualties: 2 }
            ]
        },

        intercepted_comms: {
            data: [
                { _id: 'comm_001', timestamp: '2024-12-01T02:30:00Z', source: { type: 'encrypted_channel', identifier: 'DARKNET-IRC-7749' }, sender: 'shadow_handler', recipient: 'asset_alpha', message_type: 'instruction', content: { encrypted: true, algorithm: 'AES-256', payload: 'Proceed with phase 2. Target: financial sector.' }, priority: 'high', flagged: true },
                { _id: 'comm_002', timestamp: '2024-12-01T03:00:00Z', source: { type: 'satellite_intercept', identifier: 'SAT-RELAY-42' }, sender: 'unknown', recipient: 'unknown', message_type: 'voice', content: { encrypted: false, transcript: 'The package will be delivered at midnight. Warehouse 7.' }, priority: 'medium', flagged: true },
                { _id: 'comm_003', timestamp: '2024-11-30T18:00:00Z', source: { type: 'email', identifier: 'protonmail.com' }, sender: 'contractor@secure.mail', recipient: 'client@anonymous.net', message_type: 'text', content: { encrypted: false, body: 'Payment received. Exploit ready for deployment. Zero-day for industrial control systems.' }, priority: 'critical', flagged: true },
                { _id: 'comm_004', timestamp: '2024-11-29T12:00:00Z', source: { type: 'phone_tap', identifier: '+7-XXX-XXX-XXXX' }, sender: 'foreign_operative', recipient: 'local_contact', message_type: 'voice', content: { encrypted: false, transcript: 'Meet at the usual place. Bring the documents about Project NIGHTSHADE.' }, priority: 'high', flagged: true, linked_project: 'NIGHTSHADE' },
                { _id: 'comm_005', timestamp: '2024-11-28T09:00:00Z', source: { type: 'messenger', identifier: 'Signal' }, sender: 'insider_threat', recipient: 'external_handler', message_type: 'text', content: { encrypted: true, algorithm: 'Signal Protocol', payload: 'Access granted. Uploading employee database now.' }, priority: 'critical', flagged: true }
            ]
        },

        threat_actors: {
            data: [
                { _id: 'ta_001', name: 'APT-SHADOW', origin: 'Russia', active_since: '2018', known_aliases: ['DarkBear', 'FrozenSpider', 'CryptoPhantom'], ttps: { initial_access: ['spearphishing', 'supply_chain'], persistence: ['scheduled_tasks', 'registry_keys'], exfiltration: ['dns_tunneling', 'steganography'] }, targets: ['government', 'defense', 'critical_infrastructure'], threat_level: 'severe', associated_malware: ['ShadowRAT', 'IceCrypt', 'GhostLoader'], recent_activity: '2024-12-01' },
                { _id: 'ta_002', name: 'CRYPTOLOCKER-X', origin: 'Unknown', active_since: '2023', known_aliases: ['RansomKing', 'CryptoReaper'], ttps: { initial_access: ['rdp_bruteforce', 'phishing'], encryption: ['AES-256', 'RSA-4096'], ransom: ['bitcoin', 'monero'] }, targets: ['healthcare', 'education', 'small_business'], threat_level: 'high', associated_malware: ['CryptoX', 'LockBit-Clone'], recent_activity: '2024-11-25' },
                { _id: 'ta_003', name: 'INSIDER-RING', origin: 'Internal', active_since: '2024', known_aliases: [], ttps: { recruitment: ['financial_pressure', 'ideology'], access: ['legitimate_credentials', 'social_engineering'], exfiltration: ['usb', 'cloud_upload', 'email'] }, targets: ['own_organization'], threat_level: 'critical', associated_malware: [], recent_activity: '2024-12-01', notes: 'Suspected insider threat network. At least 3 members identified.' }
            ]
        }
    }
};

// ============================================================
// QUERY ENGINE - SQL, PostgreSQL, and NoSQL Parser
// ============================================================

class QueryEngine {
    constructor(database) {
        this.db = database;
        this.currentDbType = 'sql';
    }

    setDbType(type) {
        this.currentDbType = type;
    }

    execute(query) {
        try {
            query = query.trim();

            if (this.currentDbType === 'nosql') {
                return this.executeNoSQL(query);
            } else {
                return this.executeSQL(query);
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    executeSQL(query) {
        const upperQuery = query.toUpperCase();

        if (upperQuery.startsWith('SELECT')) {
            return this.executeSelect(query);
        } else if (upperQuery.startsWith('SHOW TABLES') || upperQuery.startsWith('\\DT')) {
            return this.showTables();
        } else if (upperQuery.startsWith('DESCRIBE') || upperQuery.startsWith('\\D ')) {
            return this.describeTable(query);
        } else if (upperQuery.startsWith('SHOW DATABASES') || upperQuery.startsWith('\\L')) {
            return this.showDatabases();
        } else {
            return { success: false, error: 'Only SELECT queries are allowed in this training simulation.' };
        }
    }

    showTables() {
        const tables = Object.keys(this.db[this.currentDbType] || this.db.sql);
        return {
            success: true,
            columns: ['table_name'],
            data: tables.map(t => ({ table_name: t })),
            rowCount: tables.length
        };
    }

    showDatabases() {
        return {
            success: true,
            columns: ['database_name'],
            data: [
                { database_name: 'corpsec_main (SQL)' },
                { database_name: 'corpsec_analytics (PostgreSQL)' },
                { database_name: 'corpsec_ops (NoSQL)' }
            ],
            rowCount: 3
        };
    }

    describeTable(query) {
        let tableName;
        if (query.toUpperCase().startsWith('\\D ')) {
            tableName = query.substring(3).trim().toLowerCase();
        } else {
            tableName = query.replace(/DESCRIBE\s+/i, '').trim().toLowerCase();
        }

        const dbData = this.db[this.currentDbType] || this.db.sql;
        const table = dbData[tableName];

        if (!table) {
            return { success: false, error: `Table '${tableName}' not found.` };
        }

        return {
            success: true,
            columns: ['column_name', 'data_type', 'key'],
            data: table.columns.map(col => ({
                column_name: col.name,
                data_type: col.type,
                key: col.key || ''
            })),
            rowCount: table.columns.length
        };
    }

    executeSelect(query) {
        const parsed = this.parseSelect(query);
        if (parsed.error) {
            return { success: false, error: parsed.error };
        }

        const dbData = this.currentDbType === 'postgresql' ?
            { ...this.db.sql, ...this.db.postgresql } :
            this.db.sql;

        const table = dbData[parsed.table];
        if (!table) {
            return { success: false, error: `Table '${parsed.table}' not found.` };
        }

        let results = [...table.data];

        if (parsed.joins && parsed.joins.length > 0) {
            for (const join of parsed.joins) {
                const joinTable = dbData[join.table];
                if (!joinTable) {
                    return { success: false, error: `Table '${join.table}' not found.` };
                }
                results = this.performJoin(results, joinTable.data, join, parsed.table);
            }
        }

        if (parsed.where) {
            results = this.applyWhere(results, parsed.where);
        }

        if (parsed.groupBy) {
            results = this.applyGroupBy(results, parsed.groupBy, parsed.columns, parsed.aggregates);
        }

        if (parsed.having) {
            results = this.applyHaving(results, parsed.having);
        }

        if (parsed.orderBy) {
            results = this.applyOrderBy(results, parsed.orderBy);
        }

        if (parsed.limit) {
            results = results.slice(0, parsed.limit);
        }

        if (parsed.columns[0] !== '*' && !parsed.groupBy) {
            results = this.selectColumns(results, parsed.columns, parsed.aliases);
        }

        let columns;
        if (parsed.columns[0] === '*') {
            columns = table.columns.map(c => c.name);
        } else {
            columns = parsed.columns.map((col, i) => parsed.aliases[i] || col);
        }

        return {
            success: true,
            columns: columns,
            data: results,
            rowCount: results.length
        };
    }

    parseSelect(query) {
        const result = {
            columns: [],
            aliases: [],
            aggregates: [],
            table: null,
            joins: [],
            where: null,
            groupBy: null,
            having: null,
            orderBy: null,
            limit: null
        };

        let q = query.replace(/\s+/g, ' ').trim();

        const limitMatch = q.match(/\sLIMIT\s+(\d+)/i);
        if (limitMatch) {
            result.limit = parseInt(limitMatch[1]);
            q = q.replace(/\sLIMIT\s+\d+/i, '');
        }

        const orderMatch = q.match(/\sORDER\s+BY\s+(.+?)(?=\s*$)/i);
        if (orderMatch) {
            result.orderBy = this.parseOrderBy(orderMatch[1]);
            q = q.replace(/\sORDER\s+BY\s+.+?(?=\s*$)/i, '');
        }

        const havingMatch = q.match(/\sHAVING\s+(.+?)(?=\sORDER|\sLIMIT|\s*$)/i);
        if (havingMatch) {
            result.having = havingMatch[1].trim();
            q = q.replace(/\sHAVING\s+.+?(?=\sORDER|\sLIMIT|\s*$)/i, '');
        }

        const groupMatch = q.match(/\sGROUP\s+BY\s+(.+?)(?=\sHAVING|\sORDER|\sLIMIT|\s*$)/i);
        if (groupMatch) {
            result.groupBy = groupMatch[1].split(',').map(g => g.trim());
            q = q.replace(/\sGROUP\s+BY\s+.+?(?=\sHAVING|\sORDER|\sLIMIT|\s*$)/i, '');
        }

        const whereMatch = q.match(/\sWHERE\s+(.+?)(?=\sGROUP|\sHAVING|\sORDER|\sLIMIT|\s*$)/i);
        if (whereMatch) {
            result.where = whereMatch[1].trim();
            q = q.replace(/\sWHERE\s+.+?(?=\sGROUP|\sHAVING|\sORDER|\sLIMIT|\s*$)/i, '');
        }

        const joinRegex = /\s(INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|JOIN)\s+(\w+)(?:\s+AS\s+(\w+))?\s+ON\s+(.+?)(?=\sINNER|\sLEFT|\sRIGHT|\sJOIN|\sWHERE|\sGROUP|\sORDER|\sLIMIT|\s*$)/gi;
        let joinMatch;
        while ((joinMatch = joinRegex.exec(q)) !== null) {
            result.joins.push({
                type: joinMatch[1].toUpperCase(),
                table: joinMatch[2].toLowerCase(),
                alias: joinMatch[3] ? joinMatch[3].toLowerCase() : null,
                condition: joinMatch[4].trim()
            });
        }
        q = q.replace(joinRegex, '');

        const fromMatch = q.match(/\sFROM\s+(\w+)(?:\s+AS\s+(\w+))?/i);
        if (!fromMatch) {
            return { error: 'Invalid query: FROM clause not found.' };
        }
        result.table = fromMatch[1].toLowerCase();
        result.tableAlias = fromMatch[2] ? fromMatch[2].toLowerCase() : null;

        const selectMatch = q.match(/SELECT\s+(DISTINCT\s+)?(.+?)\s+FROM/i);
        if (!selectMatch) {
            return { error: 'Invalid query: SELECT clause not found.' };
        }
        result.distinct = !!selectMatch[1];

        const columnsStr = selectMatch[2];
        const columns = this.parseColumns(columnsStr);
        result.columns = columns.names;
        result.aliases = columns.aliases;
        result.aggregates = columns.aggregates;

        return result;
    }

    parseColumns(columnsStr) {
        const names = [];
        const aliases = [];
        const aggregates = [];

        const parts = [];
        let current = '';
        let depth = 0;
        for (const char of columnsStr) {
            if (char === '(') depth++;
            if (char === ')') depth--;
            if (char === ',' && depth === 0) {
                parts.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        if (current.trim()) parts.push(current.trim());

        for (const part of parts) {
            const aliasMatch = part.match(/(.+?)\s+AS\s+(\w+)/i);
            let colExpr = aliasMatch ? aliasMatch[1].trim() : part.trim();
            const alias = aliasMatch ? aliasMatch[2] : null;

            const aggMatch = colExpr.match(/(COUNT|SUM|AVG|MAX|MIN)\s*\(\s*(.+?)\s*\)/i);
            if (aggMatch) {
                aggregates.push({
                    function: aggMatch[1].toUpperCase(),
                    column: aggMatch[2],
                    alias: alias || colExpr
                });
                names.push(colExpr);
                aliases.push(alias || colExpr);
            } else {
                const dotMatch = colExpr.match(/(\w+)\.(\w+)/);
                if (dotMatch) {
                    names.push(dotMatch[2]);
                } else {
                    names.push(colExpr);
                }
                aliases.push(alias);
            }
        }

        return { names, aliases, aggregates };
    }

    parseOrderBy(orderStr) {
        const parts = orderStr.split(',').map(p => p.trim());
        return parts.map(part => {
            const match = part.match(/(\w+)\s*(ASC|DESC)?/i);
            return {
                column: match[1],
                direction: (match[2] || 'ASC').toUpperCase()
            };
        });
    }

    performJoin(leftData, rightData, join, leftTable) {
        const results = [];
        const condition = join.condition;

        const condMatch = condition.match(/(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)/);
        if (!condMatch) {
            return leftData;
        }

        const leftKey = condMatch[2];
        const rightKey = condMatch[4];

        for (const leftRow of leftData) {
            let matched = false;
            for (const rightRow of rightData) {
                if (leftRow[leftKey] == rightRow[rightKey]) {
                    const mergedRow = { ...leftRow };
                    for (const [key, value] of Object.entries(rightRow)) {
                        if (key in mergedRow && key !== leftKey) {
                            mergedRow[`${join.table}_${key}`] = value;
                        } else {
                            mergedRow[key] = value;
                        }
                    }
                    results.push(mergedRow);
                    matched = true;
                }
            }
            if (!matched && join.type.includes('LEFT')) {
                results.push({ ...leftRow });
            }
        }

        return results;
    }

    applyWhere(data, whereClause) {
        return data.filter(row => this.evaluateCondition(row, whereClause));
    }

    evaluateCondition(row, condition) {
        const orParts = this.splitLogical(condition, 'OR');
        if (orParts.length > 1) {
            return orParts.some(part => this.evaluateCondition(row, part.trim()));
        }

        const andParts = this.splitLogical(condition, 'AND');
        if (andParts.length > 1) {
            return andParts.every(part => this.evaluateCondition(row, part.trim()));
        }

        if (condition.startsWith('(') && condition.endsWith(')')) {
            return this.evaluateCondition(row, condition.slice(1, -1));
        }

        if (condition.toUpperCase().startsWith('NOT ')) {
            return !this.evaluateCondition(row, condition.substring(4).trim());
        }

        const inMatch = condition.match(/(\w+)\s+IN\s*\((.+)\)/i);
        if (inMatch) {
            const column = inMatch[1];
            const values = inMatch[2].split(',').map(v => v.trim().replace(/'/g, ''));
            return values.includes(String(row[column]));
        }

        const notInMatch = condition.match(/(\w+)\s+NOT\s+IN\s*\((.+)\)/i);
        if (notInMatch) {
            const column = notInMatch[1];
            const values = notInMatch[2].split(',').map(v => v.trim().replace(/'/g, ''));
            return !values.includes(String(row[column]));
        }

        const likeMatch = condition.match(/(\w+)\s+LIKE\s+'(.+)'/i);
        if (likeMatch) {
            const column = likeMatch[1];
            const pattern = likeMatch[2].replace(/%/g, '.*').replace(/_/g, '.');
            const regex = new RegExp(`^${pattern}$`, 'i');
            return regex.test(String(row[column] || ''));
        }

        const isNullMatch = condition.match(/(\w+)\s+IS\s+(NOT\s+)?NULL/i);
        if (isNullMatch) {
            const column = isNullMatch[1];
            const isNot = !!isNullMatch[2];
            const value = row[column];
            const isNull = value === null || value === undefined || value === '';
            return isNot ? !isNull : isNull;
        }

        const betweenMatch = condition.match(/(\w+)\s+BETWEEN\s+(.+)\s+AND\s+(.+)/i);
        if (betweenMatch) {
            const column = betweenMatch[1];
            const low = this.parseValue(betweenMatch[2].trim());
            const high = this.parseValue(betweenMatch[3].trim());
            const value = row[column];
            return value >= low && value <= high;
        }

        const compMatch = condition.match(/(\w+)\s*(>=|<=|!=|<>|=|>|<)\s*(.+)/);
        if (compMatch) {
            const column = compMatch[1];
            const operator = compMatch[2];
            const compareValue = this.parseValue(compMatch[3].trim());
            const rowValue = row[column];

            switch (operator) {
                case '=': return rowValue == compareValue;
                case '!=':
                case '<>': return rowValue != compareValue;
                case '>': return rowValue > compareValue;
                case '<': return rowValue < compareValue;
                case '>=': return rowValue >= compareValue;
                case '<=': return rowValue <= compareValue;
            }
        }

        return true;
    }

    splitLogical(condition, operator) {
        const parts = [];
        let temp = '';
        let depth = 0;

        for (let i = 0; i < condition.length; i++) {
            const char = condition[i];
            if (char === '(') depth++;
            if (char === ')') depth--;
            temp += char;

            const remaining = condition.substring(i + 1);
            const match = remaining.match(new RegExp(`^\\s+${operator}\\s+`, 'i'));
            if (match && depth === 0) {
                parts.push(temp);
                temp = '';
                i += match[0].length;
            }
        }
        if (temp) parts.push(temp);

        return parts.length > 0 ? parts : [condition];
    }

    parseValue(value) {
        if ((value.startsWith("'") && value.endsWith("'")) ||
            (value.startsWith('"') && value.endsWith('"'))) {
            return value.slice(1, -1);
        }
        const num = parseFloat(value);
        if (!isNaN(num)) return num;
        if (value.toUpperCase() === 'TRUE') return true;
        if (value.toUpperCase() === 'FALSE') return false;
        return value;
    }

    applyGroupBy(data, groupBy, columns, aggregates) {
        const groups = new Map();

        for (const row of data) {
            const key = groupBy.map(g => row[g]).join('|||');
            if (!groups.has(key)) {
                groups.set(key, []);
            }
            groups.get(key).push(row);
        }

        const results = [];
        for (const [key, rows] of groups) {
            const result = {};

            for (const col of groupBy) {
                result[col] = rows[0][col];
            }

            for (const agg of aggregates) {
                const colName = agg.column === '*' ? null : agg.column;
                let value;

                switch (agg.function) {
                    case 'COUNT':
                        value = colName ? rows.filter(r => r[colName] != null).length : rows.length;
                        break;
                    case 'SUM':
                        value = rows.reduce((sum, r) => sum + (parseFloat(r[colName]) || 0), 0);
                        break;
                    case 'AVG':
                        const nums = rows.map(r => parseFloat(r[colName])).filter(n => !isNaN(n));
                        value = nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : 0;
                        break;
                    case 'MAX':
                        value = Math.max(...rows.map(r => r[colName]).filter(v => v != null));
                        break;
                    case 'MIN':
                        value = Math.min(...rows.map(r => r[colName]).filter(v => v != null));
                        break;
                }

                result[agg.alias] = value;
            }

            results.push(result);
        }

        return results;
    }

    applyHaving(data, havingClause) {
        return data.filter(row => this.evaluateCondition(row, havingClause));
    }

    applyOrderBy(data, orderBy) {
        return [...data].sort((a, b) => {
            for (const order of orderBy) {
                const aVal = a[order.column];
                const bVal = b[order.column];

                let comparison = 0;
                if (aVal < bVal) comparison = -1;
                if (aVal > bVal) comparison = 1;

                if (comparison !== 0) {
                    return order.direction === 'DESC' ? -comparison : comparison;
                }
            }
            return 0;
        });
    }

    selectColumns(data, columns, aliases) {
        return data.map(row => {
            const result = {};
            for (let i = 0; i < columns.length; i++) {
                const col = columns[i];
                const alias = aliases[i] || col;
                result[alias] = row[col];
            }
            return result;
        });
    }

    // NoSQL Query Execution
    executeNoSQL(query) {
        try {
            query = query.trim();

            const match = query.match(/db\.(\w+)\.(\w+)\(([\s\S]*)\)/);
            if (!match) {
                return { success: false, error: 'Invalid NoSQL query syntax. Use: db.collection.method({query})' };
            }

            const collection = match[1];
            const method = match[2];
            const argsStr = match[3].trim();

            const collectionData = this.db.nosql[collection];
            if (!collectionData) {
                return { success: false, error: `Collection '${collection}' not found.` };
            }

            let args = [];
            if (argsStr) {
                try {
                    args = this.parseNoSQLArgs(argsStr);
                } catch (e) {
                    return { success: false, error: `Invalid query arguments: ${e.message}` };
                }
            }

            switch (method.toLowerCase()) {
                case 'find':
                    return this.noSQLFind(collectionData.data, args[0] || {}, args[1]);
                case 'findone':
                    return this.noSQLFindOne(collectionData.data, args[0] || {});
                case 'count':
                    return this.noSQLCount(collectionData.data, args[0] || {});
                case 'distinct':
                    return this.noSQLDistinct(collectionData.data, args[0], args[1] || {});
                case 'aggregate':
                    return this.noSQLAggregate(collectionData.data, args[0] || []);
                default:
                    return { success: false, error: `Method '${method}' is not supported in this simulation.` };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    parseNoSQLArgs(argsStr) {
        const args = [];
        let depth = 0;
        let current = '';

        for (let i = 0; i < argsStr.length; i++) {
            const char = argsStr[i];
            if (char === '{' || char === '[') depth++;
            if (char === '}' || char === ']') depth--;

            if (char === ',' && depth === 0) {
                if (current.trim()) {
                    args.push(this.parseNoSQLObject(current.trim()));
                }
                current = '';
            } else {
                current += char;
            }
        }
        if (current.trim()) {
            args.push(this.parseNoSQLObject(current.trim()));
        }

        return args;
    }

    parseNoSQLObject(str) {
        if (str.startsWith('"') || str.startsWith("'")) {
            return str.slice(1, -1);
        }

        try {
            let normalized = str
                .replace(/'/g, '"')
                .replace(/([{,]\s*)(\w+)\s*:/g, '$1"$2":')
                .replace(/:\s*'([^']+)'/g, ':"$1"');

            return JSON.parse(normalized);
        } catch (e) {
            if (str === 'true') return true;
            if (str === 'false') return false;
            if (str === 'null') return null;
            const num = parseFloat(str);
            if (!isNaN(num)) return num;
            return str;
        }
    }

    noSQLFind(data, query, projection) {
        let results = data.filter(doc => this.matchNoSQLQuery(doc, query));

        if (projection) {
            results = results.map(doc => {
                const projected = { _id: doc._id };
                for (const [key, value] of Object.entries(projection)) {
                    if (value === 1 || value === true) {
                        projected[key] = doc[key];
                    }
                }
                return projected;
            });
        }

        return {
            success: true,
            type: 'nosql',
            data: results,
            rowCount: results.length
        };
    }

    noSQLFindOne(data, query) {
        const result = data.find(doc => this.matchNoSQLQuery(doc, query));
        return {
            success: true,
            type: 'nosql',
            data: result ? [result] : [],
            rowCount: result ? 1 : 0
        };
    }

    noSQLCount(data, query) {
        const count = data.filter(doc => this.matchNoSQLQuery(doc, query)).length;
        return {
            success: true,
            type: 'nosql',
            data: [{ count }],
            rowCount: 1
        };
    }

    noSQLDistinct(data, field, query) {
        const filtered = data.filter(doc => this.matchNoSQLQuery(doc, query));
        const values = [...new Set(filtered.map(doc => doc[field]).filter(v => v !== undefined))];
        return {
            success: true,
            type: 'nosql',
            data: values.map(v => ({ [field]: v })),
            rowCount: values.length
        };
    }

    noSQLAggregate(data, pipeline) {
        let results = [...data];

        for (const stage of pipeline) {
            const stageName = Object.keys(stage)[0];
            const stageValue = stage[stageName];

            switch (stageName) {
                case '$match':
                    results = results.filter(doc => this.matchNoSQLQuery(doc, stageValue));
                    break;
                case '$project':
                    results = results.map(doc => {
                        const projected = {};
                        for (const [key, value] of Object.entries(stageValue)) {
                            if (value === 1 || value === true) {
                                projected[key] = doc[key];
                            } else if (typeof value === 'string' && value.startsWith('$')) {
                                projected[key] = doc[value.substring(1)];
                            }
                        }
                        return projected;
                    });
                    break;
                case '$group':
                    results = this.noSQLGroup(results, stageValue);
                    break;
                case '$sort':
                    results = this.noSQLSort(results, stageValue);
                    break;
                case '$limit':
                    results = results.slice(0, stageValue);
                    break;
                case '$unwind':
                    results = this.noSQLUnwind(results, stageValue);
                    break;
            }
        }

        return {
            success: true,
            type: 'nosql',
            data: results,
            rowCount: results.length
        };
    }

    matchNoSQLQuery(doc, query) {
        if (!query || Object.keys(query).length === 0) return true;

        for (const [key, value] of Object.entries(query)) {
            if (key === '$and') {
                if (!value.every(q => this.matchNoSQLQuery(doc, q))) return false;
                continue;
            }
            if (key === '$or') {
                if (!value.some(q => this.matchNoSQLQuery(doc, q))) return false;
                continue;
            }

            const docValue = this.getNestedValue(doc, key);

            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                for (const [op, opValue] of Object.entries(value)) {
                    switch (op) {
                        case '$eq': if (docValue != opValue) return false; break;
                        case '$ne': if (docValue == opValue) return false; break;
                        case '$gt': if (!(docValue > opValue)) return false; break;
                        case '$gte': if (!(docValue >= opValue)) return false; break;
                        case '$lt': if (!(docValue < opValue)) return false; break;
                        case '$lte': if (!(docValue <= opValue)) return false; break;
                        case '$in': if (!opValue.includes(docValue)) return false; break;
                        case '$nin': if (opValue.includes(docValue)) return false; break;
                        case '$exists': if ((docValue !== undefined) !== opValue) return false; break;
                        case '$regex':
                            const regex = new RegExp(opValue, 'i');
                            if (!regex.test(docValue)) return false;
                            break;
                        case '$elemMatch':
                            if (!Array.isArray(docValue)) return false;
                            if (!docValue.some(elem => this.matchNoSQLQuery(elem, opValue))) return false;
                            break;
                    }
                }
            } else if (Array.isArray(value)) {
                if (!Array.isArray(docValue) || JSON.stringify(docValue) !== JSON.stringify(value)) {
                    return false;
                }
            } else {
                if (docValue != value) return false;
            }
        }

        return true;
    }

    getNestedValue(obj, path) {
        const parts = path.split('.');
        let current = obj;
        for (const part of parts) {
            if (current === undefined || current === null) return undefined;
            current = current[part];
        }
        return current;
    }

    noSQLGroup(data, groupSpec) {
        const groups = new Map();
        const idSpec = groupSpec._id;

        for (const doc of data) {
            let groupKey;
            if (typeof idSpec === 'string' && idSpec.startsWith('$')) {
                groupKey = doc[idSpec.substring(1)];
            } else if (typeof idSpec === 'object') {
                groupKey = JSON.stringify(Object.fromEntries(
                    Object.entries(idSpec).map(([k, v]) => [k, v.startsWith('$') ? doc[v.substring(1)] : v])
                ));
            } else {
                groupKey = idSpec;
            }

            if (!groups.has(groupKey)) {
                groups.set(groupKey, []);
            }
            groups.get(groupKey).push(doc);
        }

        const results = [];
        for (const [key, docs] of groups) {
            const result = { _id: typeof key === 'string' && key.startsWith('{') ? JSON.parse(key) : key };

            for (const [field, expr] of Object.entries(groupSpec)) {
                if (field === '_id') continue;

                if (typeof expr === 'object') {
                    const op = Object.keys(expr)[0];
                    const opField = expr[op];
                    const fieldName = typeof opField === 'string' && opField.startsWith('$') ? opField.substring(1) : null;

                    switch (op) {
                        case '$sum':
                            result[field] = opField === 1 ? docs.length : docs.reduce((sum, d) => sum + (d[fieldName] || 0), 0);
                            break;
                        case '$avg':
                            const vals = docs.map(d => d[fieldName]).filter(v => typeof v === 'number');
                            result[field] = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : 0;
                            break;
                        case '$max':
                            result[field] = Math.max(...docs.map(d => d[fieldName]).filter(v => v != null));
                            break;
                        case '$min':
                            result[field] = Math.min(...docs.map(d => d[fieldName]).filter(v => v != null));
                            break;
                        case '$push':
                            result[field] = docs.map(d => d[fieldName]);
                            break;
                        case '$first':
                            result[field] = docs[0] ? docs[0][fieldName] : null;
                            break;
                    }
                }
            }

            results.push(result);
        }

        return results;
    }

    noSQLSort(data, sortSpec) {
        return [...data].sort((a, b) => {
            for (const [field, direction] of Object.entries(sortSpec)) {
                const aVal = a[field];
                const bVal = b[field];
                if (aVal < bVal) return direction === -1 ? 1 : -1;
                if (aVal > bVal) return direction === -1 ? -1 : 1;
            }
            return 0;
        });
    }

    noSQLUnwind(data, field) {
        const fieldName = field.startsWith('$') ? field.substring(1) : field;
        const results = [];

        for (const doc of data) {
            const arrayValue = doc[fieldName];
            if (Array.isArray(arrayValue)) {
                for (const item of arrayValue) {
                    results.push({ ...doc, [fieldName]: item });
                }
            } else {
                results.push(doc);
            }
        }

        return results;
    }
}

// ============================================================
// CODE VALIDATOR
// ============================================================

class CodeValidator {
    constructor() {
        this.currentLanguage = 'python';
    }

    setLanguage(lang) {
        this.currentLanguage = lang;
    }

    getTemplate(level, language) {
        const templates = {
            python: {
                sql: `# Python SQL Implementation
# ============================================================
# Required Libraries:
#   pip install sqlite3    (built-in)
#   pip install psycopg2   (for PostgreSQL)
#   pip install mysql-connector-python  (for MySQL)
# ============================================================

import sqlite3
# Alternative for PostgreSQL:
# import psycopg2

def execute_query(connection):
    """
    Execute SQL query and return results.

    Args:
        connection: Database connection object
    Returns:
        List of tuples containing query results
    """
    cursor = connection.cursor()

    # TODO: Write your SQL query here
    query = """
        YOUR QUERY HERE
    """

    cursor.execute(query)
    results = cursor.fetchall()
    return results


# Example usage:
# conn = sqlite3.connect('database.db')
# results = execute_query(conn)
# conn.close()`,

                postgresql: `# Python PostgreSQL Implementation
# ============================================================
# Required Libraries:
#   pip install psycopg2-binary
#
# Documentation: https://www.psycopg.org/docs/
# ============================================================

import psycopg2
from psycopg2.extras import RealDictCursor

def execute_query(connection):
    """
    Execute PostgreSQL query and return results as dictionaries.

    Args:
        connection: psycopg2 connection object
    Returns:
        List of dictionaries containing query results
    """
    cursor = connection.cursor(cursor_factory=RealDictCursor)

    # TODO: Write your PostgreSQL query here
    # PostgreSQL-specific features available:
    #   - JSONB operators: ->, ->>, @>, ?
    #   - Array operations: ANY(), ALL(), array_agg()
    #   - Window functions: ROW_NUMBER(), RANK()
    query = """
        YOUR QUERY HERE
    """

    cursor.execute(query)
    results = cursor.fetchall()
    return results


# Example usage:
# conn = psycopg2.connect(
#     host="localhost",
#     database="mydb",
#     user="user",
#     password="password"
# )
# results = execute_query(conn)
# conn.close()`,

                nosql: `# Python MongoDB Implementation
# ============================================================
# Required Libraries:
#   pip install pymongo
#
# Documentation: https://pymongo.readthedocs.io/
# ============================================================

from pymongo import MongoClient

def execute_query(collection):
    """
    Execute MongoDB query and return results.

    Args:
        collection: pymongo collection object
    Returns:
        List of documents matching the query
    """
    # TODO: Write your MongoDB query here
    # Common operators:
    #   $eq, $ne, $gt, $gte, $lt, $lte
    #   $in, $nin, $exists, $regex
    #   $and, $or, $not
    query = {
        # YOUR QUERY HERE
    }

    results = list(collection.find(query))
    return results


# Example usage:
# client = MongoClient('mongodb://localhost:27017/')
# db = client['database_name']
# collection = db['collection_name']
# results = execute_query(collection)
# client.close()`
            },

            go: {
                sql: `// Go SQL Implementation
// ============================================================
// Required Libraries:
//   go get github.com/lib/pq          (PostgreSQL)
//   go get github.com/go-sql-driver/mysql  (MySQL)
//   go get github.com/mattn/go-sqlite3     (SQLite)
//
// Documentation: https://pkg.go.dev/database/sql
// ============================================================

package main

import (
    "database/sql"
    "fmt"

    _ "github.com/lib/pq"  // PostgreSQL driver
    // _ "github.com/go-sql-driver/mysql"  // MySQL driver
)

func executeQuery(db *sql.DB) ([]map[string]interface{}, error) {
    // TODO: Write your SQL query here
    query := \`
        YOUR QUERY HERE
    \`

    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    columns, _ := rows.Columns()
    var results []map[string]interface{}

    for rows.Next() {
        values := make([]interface{}, len(columns))
        valuePtrs := make([]interface{}, len(columns))
        for i := range columns {
            valuePtrs[i] = &values[i]
        }
        rows.Scan(valuePtrs...)
        row := make(map[string]interface{})
        for i, col := range columns {
            row[col] = values[i]
        }
        results = append(results, row)
    }
    return results, nil
}

// Example usage:
// db, err := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
// if err != nil { log.Fatal(err) }
// defer db.Close()
// results, err := executeQuery(db)`,

                postgresql: `// Go PostgreSQL Implementation
// ============================================================
// Required Libraries:
//   go get github.com/lib/pq
//   go get github.com/jackc/pgx/v5  (alternative, more features)
//
// Documentation: https://pkg.go.dev/github.com/lib/pq
// ============================================================

package main

import (
    "database/sql"
    "encoding/json"

    _ "github.com/lib/pq"
    "github.com/lib/pq"  // For pq.Array()
)

func executeQuery(db *sql.DB) ([]map[string]interface{}, error) {
    // TODO: Write your PostgreSQL query here
    // PostgreSQL-specific features:
    //   - Use json.RawMessage for JSONB columns
    //   - Use pq.Array() for array columns
    query := \`
        YOUR QUERY HERE
    \`

    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    columns, _ := rows.Columns()
    var results []map[string]interface{}

    for rows.Next() {
        values := make([]interface{}, len(columns))
        valuePtrs := make([]interface{}, len(columns))
        for i := range columns {
            valuePtrs[i] = &values[i]
        }
        rows.Scan(valuePtrs...)
        row := make(map[string]interface{})
        for i, col := range columns {
            row[col] = values[i]
        }
        results = append(results, row)
    }
    return results, nil
}

// Example usage:
// connStr := "postgres://user:pass@localhost/dbname?sslmode=disable"
// db, err := sql.Open("postgres", connStr)
// if err != nil { log.Fatal(err) }
// defer db.Close()
// results, err := executeQuery(db)`,

                nosql: `// Go MongoDB Implementation
// ============================================================
// Required Libraries:
//   go get go.mongodb.org/mongo-driver/mongo
//   go get go.mongodb.org/mongo-driver/bson
//
// Documentation: https://pkg.go.dev/go.mongodb.org/mongo-driver
// ============================================================

package main

import (
    "context"
    "log"
    "time"

    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

func executeQuery(collection *mongo.Collection) ([]bson.M, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // TODO: Write your MongoDB query here
    // Common filter operators:
    //   bson.M{"field": "value"}           - exact match
    //   bson.M{"field": bson.M{"$gt": 5}}  - greater than
    //   bson.M{"field": bson.M{"$in": []}} - in array
    filter := bson.M{
        // YOUR QUERY HERE
    }

    cursor, err := collection.Find(ctx, filter)
    if err != nil {
        return nil, err
    }
    defer cursor.Close(ctx)

    var results []bson.M
    if err := cursor.All(ctx, &results); err != nil {
        return nil, err
    }
    return results, nil
}

// Example usage:
// ctx := context.Background()
// client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
// if err != nil { log.Fatal(err) }
// defer client.Disconnect(ctx)
// collection := client.Database("dbname").Collection("collname")
// results, err := executeQuery(collection)`
            }
        };

        return templates[language][level.dbType] || templates[language].sql;
    }

    validate(code, level, language) {
        const validation = {
            passed: false,
            errors: [],
            warnings: [],
            score: 0
        };

        if (!code || code.trim().length === 0) {
            validation.errors.push('No code provided.');
            return validation;
        }

        const requirements = this.getRequirements(level, language);

        for (const req of requirements.required) {
            if (!this.checkPattern(code, req.pattern)) {
                validation.errors.push(req.message);
            }
        }

        for (const req of requirements.recommended) {
            if (!this.checkPattern(code, req.pattern)) {
                validation.warnings.push(req.message);
            }
        }

        for (const forbidden of requirements.forbidden) {
            if (this.checkPattern(code, forbidden.pattern)) {
                validation.errors.push(forbidden.message);
            }
        }

        const queryMatch = this.extractAndValidateQuery(code, level, language);
        if (!queryMatch.valid) {
            validation.errors.push(queryMatch.error);
        } else {
            validation.score += 50;
        }

        if (validation.errors.length === 0) {
            validation.passed = true;
            validation.score += 50;
            validation.score -= validation.warnings.length * 10;
            validation.score = Math.max(validation.score, 10);
        }

        return validation;
    }

    getRequirements(level, language) {
        const requirements = {
            required: [],
            recommended: [],
            forbidden: []
        };

        if (language === 'python') {
            if (level.dbType === 'sql' || level.dbType === 'postgresql') {
                requirements.required.push(
                    { pattern: /cursor\s*[=.]|\.cursor\(\)/, message: 'Must create a database cursor.' },
                    { pattern: /\.execute\s*\(/, message: 'Must execute the query using cursor.execute().' },
                    { pattern: /\.fetch(all|one|many)\s*\(/, message: 'Must fetch results using fetchall(), fetchone(), or fetchmany().' }
                );
                requirements.forbidden.push(
                    { pattern: /f["'].*\{.*\}.*["']|%s|\.format\(/, message: 'WARNING: Avoid string interpolation - use parameterized queries!' }
                );
            } else if (level.dbType === 'nosql') {
                requirements.required.push(
                    { pattern: /collection\.(find|find_one|aggregate|count|distinct)/, message: 'Must use a MongoDB collection method.' }
                );
            }
        } else if (language === 'go') {
            if (level.dbType === 'sql' || level.dbType === 'postgresql') {
                requirements.required.push(
                    { pattern: /db\.Query|db\.QueryRow/, message: 'Must execute query using db.Query() or db.QueryRow().' },
                    { pattern: /rows\.Scan|row\.Scan/, message: 'Must scan results using Scan().' },
                    { pattern: /defer\s+rows\.Close\(\)/, message: 'Must defer closing rows.' }
                );
            } else if (level.dbType === 'nosql') {
                requirements.required.push(
                    { pattern: /collection\.(Find|FindOne|Aggregate)/, message: 'Must use a MongoDB collection method.' },
                    { pattern: /cursor\.(All|Next|Decode)/, message: 'Must process cursor results.' }
                );
            }
        }

        return requirements;
    }

    checkPattern(code, pattern) {
        if (pattern instanceof RegExp) {
            return pattern.test(code);
        }
        return code.includes(pattern);
    }

    extractAndValidateQuery(code, level, language) {
        let query = '';

        if (language === 'python') {
            const tripleMatch = code.match(/query\s*=\s*(?:f)?(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')/);
            const singleMatch = code.match(/query\s*=\s*(?:f)?["']([^"']+)["']/);
            const findMatch = code.match(/collection\.(find|find_one|aggregate)\s*\(([\s\S]*?)\)/);

            if (tripleMatch) {
                query = tripleMatch[1] || tripleMatch[2];
            } else if (singleMatch) {
                query = singleMatch[1];
            } else if (findMatch) {
                query = findMatch[0];
            }
        } else if (language === 'go') {
            const backtickMatch = code.match(/query\s*:?=\s*`([\s\S]*?)`/);
            const stringMatch = code.match(/query\s*:?=\s*"([^"]+)"/);
            const filterMatch = code.match(/filter\s*:?=\s*bson\.M\s*\{([\s\S]*?)\}/);

            if (backtickMatch) {
                query = backtickMatch[1];
            } else if (stringMatch) {
                query = stringMatch[1];
            } else if (filterMatch) {
                query = filterMatch[0];
            }
        }

        if (!query || query.includes('YOUR QUERY HERE')) {
            return { valid: false, error: 'Query not implemented - replace the placeholder with your actual query.' };
        }

        const expectedKeywords = level.expectedKeywords || [];
        const missingKeywords = [];

        for (const keyword of expectedKeywords) {
            const regex = new RegExp(keyword, 'i');
            if (!regex.test(query)) {
                missingKeywords.push(keyword);
            }
        }

        if (missingKeywords.length > 0) {
            return {
                valid: false,
                error: `Query may be incorrect. Consider using: ${missingKeywords.join(', ')}`
            };
        }

        return { valid: true };
    }

    getHint(level, language, hintLevel = 1) {
        const hints = {
            python: {
                sql: [
                    'Remember to create a cursor from the connection before executing queries.',
                    'Use cursor.execute(query) to run your SQL, then cursor.fetchall() to get results.',
                    `For this mission, your query should ${level.queryHint || 'retrieve the required data'}.`
                ],
                postgresql: [
                    'PostgreSQL supports JSONB operations with operators like -> and ->>',
                    'Use RealDictCursor from psycopg2.extras for dictionary results.',
                    'Array operations like ANY() and array_agg() can be very powerful.'
                ],
                nosql: [
                    'MongoDB find() takes a query document as its first argument.',
                    'Use operators like $gt, $lt, $in for comparisons in your query.',
                    'For complex queries, consider using the aggregation pipeline.'
                ]
            },
            go: {
                sql: [
                    'Use db.Query() for multiple rows or db.QueryRow() for a single row.',
                    'Always defer rows.Close() to prevent resource leaks.',
                    'Scan each row into variables matching your SELECT columns.'
                ],
                postgresql: [
                    'Use the pq driver for PostgreSQL-specific features.',
                    'JSONB columns can be scanned into json.RawMessage.',
                    'Use pq.Array() to scan PostgreSQL array types.'
                ],
                nosql: [
                    'Use bson.M{} for query filters in MongoDB Go driver.',
                    'Always close cursors with defer cursor.Close(ctx).',
                    'Use cursor.All() to decode all results at once.'
                ]
            }
        };

        const langHints = hints[language]?.[level.dbType] || hints[language]?.sql || [];
        return langHints[Math.min(hintLevel - 1, langHints.length - 1)] || 'No additional hints available.';
    }
}

// ============================================================
// GAME LEVELS
// ============================================================

const GameLevels = [
    // SQL BASICS (Levels 1-4)
    {
        id: 1,
        title: 'First Contact',
        dbType: 'sql',
        difficulty: 'beginner',
        briefing: `MISSION BRIEFING: Welcome to your first operation, recruit.

We've gained access to CorpSec's employee database. Your objective is simple: retrieve a list of all users in the system.

OBJECTIVE: Select all columns from the 'users' table.

HINT: Use SELECT * FROM table_name`,
        tables: ['users'],
        expectedQuery: /SELECT\s+\*\s+FROM\s+users/i,
        expectedKeywords: ['SELECT', 'FROM', 'users'],
        queryHint: 'select all columns from the users table',
        validation: (results) => results.length === 7 && results[0].username !== undefined,
        successMessage: 'Excellent work! You\'ve retrieved the user list. Notice the suspicious "ghost_user" account...',
        intel: '7 user accounts identified. Suspicious account detected: ghost_user@darknet.onion',
        points: 100
    },
    {
        id: 2,
        title: 'Filtering Intel',
        dbType: 'sql',
        difficulty: 'beginner',
        briefing: `MISSION BRIEFING: We need to narrow down our search.

Find all users whose status is marked as 'suspicious'.

OBJECTIVE: Select all users where status equals 'suspicious'.

HINT: Use WHERE clause: WHERE column = 'value'`,
        tables: ['users'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+users\s+WHERE\s+status\s*=\s*['"]suspicious['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'users', 'WHERE', 'status'],
        queryHint: 'filter users by status',
        validation: (results) => results.length === 1 && results[0].username === 'ghost_user',
        successMessage: 'Target acquired! The ghost_user account is confirmed suspicious.',
        intel: 'Suspicious user identified: ghost_user (ID: 4). Email: shadow@darknet.onion',
        points: 150
    },
    {
        id: 3,
        title: 'Access Trail',
        dbType: 'sql',
        difficulty: 'beginner',
        briefing: `MISSION BRIEFING: Trace the ghost_user's activities.

Access the access_logs table and find all entries for user_id 4.

OBJECTIVE: Retrieve all access logs for user_id = 4.`,
        tables: ['users', 'access_logs'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+access_logs\s+WHERE\s+user_id\s*=\s*4/i,
        expectedKeywords: ['SELECT', 'FROM', 'access_logs', 'WHERE', 'user_id'],
        queryHint: 'filter access_logs by user_id',
        validation: (results) => results.length >= 4 && results.every(r => r.user_id === 4),
        successMessage: 'Critical intelligence obtained! Ghost_user has been downloading classified files!',
        intel: 'ghost_user activities: LOGIN, DOWNLOAD (classified.zip), DELETE attempt, UPLOAD (backdoor.sh)',
        points: 150
    },
    {
        id: 4,
        title: 'Joining Forces',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Combine users and access_logs tables.

Focus on actions related to the '/secrets/' path.

OBJECTIVE: JOIN users and access_logs, filter for resources containing '/secrets/'.

HINT: Use JOIN ... ON and LIKE '%pattern%'`,
        tables: ['users', 'access_logs'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+(users|access_logs)\s+(INNER\s+)?JOIN\s+(users|access_logs)\s+ON\s+.+WHERE\s+.+LIKE\s+['"]%.*secrets.*%['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'JOIN', 'ON', 'WHERE', 'LIKE', 'secrets'],
        queryHint: 'join users with access_logs and filter by resource path',
        validation: (results) => results.length >= 1 && results.some(r => r.resource?.includes('/secrets/')),
        successMessage: 'Connection established! We now know exactly who accessed the classified files.',
        intel: 'ghost_user downloaded /secrets/classified.zip at 03:35:00',
        points: 200
    },

    // SQL INTERMEDIATE (Levels 5-7)
    {
        id: 5,
        title: 'Money Trail',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Follow the money.

Find all transactions over $100,000 ordered by amount descending.

OBJECTIVE: Select from transactions where amount > 100000, ORDER BY amount DESC.`,
        tables: ['transactions'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+transactions\s+WHERE\s+amount\s*>\s*100000.*ORDER\s+BY\s+amount\s+DESC/i,
        expectedKeywords: ['SELECT', 'FROM', 'transactions', 'WHERE', 'amount', 'ORDER BY', 'DESC'],
        queryHint: 'filter transactions by amount and order descending',
        validation: (results) => results.length >= 2 && results[0].amount >= results[results.length - 1].amount,
        successMessage: 'Financial trail uncovered! Large sums moving to offshore accounts.',
        intel: 'Suspicious transfers: $175,000 to ACC-888-SHELL, then $174,500 to ACC-777-CAYMAN',
        points: 200
    },
    {
        id: 6,
        title: 'Aggregate Intelligence',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: We need statistical analysis.

Count how many access log entries exist for each user_id.

OBJECTIVE: Use COUNT and GROUP BY to aggregate access_logs by user_id.`,
        tables: ['access_logs'],
        expectedQuery: /SELECT\s+.*(user_id|COUNT).*\s+FROM\s+access_logs\s+.*GROUP\s+BY\s+user_id/i,
        expectedKeywords: ['SELECT', 'COUNT', 'FROM', 'access_logs', 'GROUP BY', 'user_id'],
        queryHint: 'group access_logs by user_id and count entries',
        validation: (results) => results.length >= 3 && results.some(r => r['COUNT(*)'] !== undefined || r.count !== undefined),
        successMessage: 'Pattern analysis complete! Ghost_user has the most suspicious activity.',
        intel: 'Activity count by user: ghost_user leads with 5 logged actions',
        points: 250
    },
    {
        id: 7,
        title: 'The Vault',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Penetrate the credentials vault.

Find credentials for servers with 'top_secret' classification.

OBJECTIVE: Join credentials and servers, filter for classification = 'top_secret'.`,
        tables: ['credentials', 'servers'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+(credentials|servers)\s+(INNER\s+)?JOIN\s+(credentials|servers)\s+ON\s+.+WHERE\s+.*classification\s*=\s*['"]top_secret['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'JOIN', 'ON', 'WHERE', 'classification', 'top_secret'],
        queryHint: 'join credentials with servers and filter by classification',
        validation: (results) => results.length >= 1 && results.some(r => r.encrypted_password?.includes('FLAG{SQL_MASTER}') || r.service_name === 'VaultAPI'),
        successMessage: 'VAULT BREACHED! You\'ve found credentials for the secret vault server!',
        intel: 'FLAG{SQL_MASTER} - VaultAPI credentials obtained',
        points: 300
    },

    // POSTGRESQL LEVELS (8-11)
    {
        id: 8,
        title: 'Network Recon',
        dbType: 'postgresql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Switching to PostgreSQL analytics database.

Find all hosts with risk_score above 8.0.

OBJECTIVE: Query network_scans for risk_score > 8.0.`,
        tables: ['network_scans'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+network_scans\s+WHERE\s+risk_score\s*>\s*8/i,
        expectedKeywords: ['SELECT', 'FROM', 'network_scans', 'WHERE', 'risk_score'],
        queryHint: 'filter network_scans by risk_score',
        validation: (results) => results.length >= 1 && results.every(r => r.risk_score > 8.0),
        successMessage: 'Critical vulnerabilities identified!',
        intel: '2 critical systems: legacy-app (9.8) with MS17-010, honeypot-01 (10.0) with BACKDOOR',
        points: 250
    },
    {
        id: 9,
        title: 'Threat Intel',
        dbType: 'postgresql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Analyze the threat intelligence database.

Find all indicators associated with 'APT-SHADOW'.

OBJECTIVE: Query threat_intel for threat_actor = 'APT-SHADOW'.`,
        tables: ['threat_intel'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+threat_intel\s+WHERE\s+threat_actor\s*=\s*['"]APT-SHADOW['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'threat_intel', 'WHERE', 'threat_actor', 'APT-SHADOW'],
        queryHint: 'filter threat_intel by threat_actor',
        validation: (results) => results.length >= 3 && results.every(r => r.threat_actor === 'APT-SHADOW'),
        successMessage: 'Threat actor profile compiled!',
        intel: 'APT-SHADOW indicators: IP 185.234.72.19, domain evil-domain.tk, email shadow@darknet.onion',
        points: 300
    },
    {
        id: 10,
        title: 'The Breach Timeline',
        dbType: 'postgresql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Reconstruct the breach timeline.

Query audit_events for all events by 'ghost_user' ordered by timestamp.

OBJECTIVE: Get all audit events for ghost_user, ordered chronologically.`,
        tables: ['audit_events'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+audit_events\s+WHERE\s+actor\s*=\s*['"]ghost_user['"].*ORDER\s+BY\s+event_time/i,
        expectedKeywords: ['SELECT', 'FROM', 'audit_events', 'WHERE', 'actor', 'ghost_user', 'ORDER BY'],
        queryHint: 'filter audit_events by actor and order by time',
        validation: (results) => results.length >= 5 && results.every(r => r.actor === 'ghost_user'),
        successMessage: 'Breach timeline reconstructed!',
        intel: 'Attack sequence: auth -> privilege_escalation -> data_exfiltration -> log_tampering -> backdoor',
        points: 350
    },
    {
        id: 11,
        title: 'Vulnerability Analysis',
        dbType: 'postgresql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Deep analysis required.

Find scans where vulnerabilities contain 'BACKDOOR-DETECTED'.

OBJECTIVE: Query for scans with backdoor vulnerabilities.

HINT: Search in the vulnerabilities array for 'BACKDOOR-DETECTED'`,
        tables: ['network_scans'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+network_scans\s+WHERE\s+.*('BACKDOOR-DETECTED'\s*=\s*ANY|vulnerabilities\s*@>|BACKDOOR)/i,
        expectedKeywords: ['SELECT', 'FROM', 'network_scans', 'WHERE', 'BACKDOOR'],
        queryHint: 'search for backdoor in vulnerabilities array',
        validation: (results) => results.length >= 1 && results.some(r => r.vulnerabilities?.includes('BACKDOOR-DETECTED')),
        successMessage: 'Backdoor confirmed! The honeypot has been compromised.',
        intel: 'BACKDOOR-DETECTED on 10.0.0.99 (honeypot-01)',
        points: 350
    },

    // NOSQL LEVELS (12-15)
    {
        id: 12,
        title: 'Agent Files',
        dbType: 'nosql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Switching to NoSQL operations database.

Find all active agents.

OBJECTIVE: Use db.agents.find() to query for status = "active".

HINT: db.collection.find({field: "value"})`,
        tables: ['agents'],
        expectedQuery: /db\.agents\.find\s*\(\s*\{.*status.*active.*\}/i,
        expectedKeywords: ['db', 'agents', 'find', 'status', 'active'],
        queryHint: 'find documents where status equals active',
        validation: (results) => results.length >= 3 && results.every(r => r.status === 'active'),
        successMessage: 'Agent roster accessed! 4 active operatives identified.',
        intel: 'Active agents: VIPER (Berlin), GHOST (Tokyo), SPECTER (London), ORACLE (Langley)',
        points: 250
    },
    {
        id: 13,
        title: 'Mission Archive',
        dbType: 'nosql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Access the missions collection.

Find all completed missions with outcome = 'success'.

OBJECTIVE: Query for status="completed" AND outcome="success".

HINT: {field1: "val1", field2: "val2"}`,
        tables: ['missions'],
        expectedQuery: /db\.missions\.find\s*\(\s*\{.*status.*completed.*outcome.*success|outcome.*success.*status.*completed.*\}/i,
        expectedKeywords: ['db', 'missions', 'find', 'status', 'completed', 'outcome', 'success'],
        queryHint: 'find missions with multiple conditions',
        validation: (results) => results.length >= 2 && results.every(r => r.status === 'completed' && r.outcome === 'success'),
        successMessage: 'Mission archives decrypted!',
        intel: 'Successful missions: DARK_HARVEST, IRON_CURTAIN',
        points: 300
    },
    {
        id: 14,
        title: 'Intercepted Communications',
        dbType: 'nosql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Critical intercepts require analysis.

Find all communications with priority = "critical".

OBJECTIVE: Query intercepted_comms for priority = "critical".`,
        tables: ['intercepted_comms'],
        expectedQuery: /db\.intercepted_comms\.find\s*\(\s*\{.*priority.*critical.*\}/i,
        expectedKeywords: ['db', 'intercepted_comms', 'find', 'priority', 'critical'],
        queryHint: 'find communications by priority level',
        validation: (results) => results.length >= 2 && results.every(r => r.priority === 'critical'),
        successMessage: 'Critical intercepts obtained!',
        intel: 'CRITICAL: Zero-day exploit and insider threat detected!',
        points: 350
    },
    {
        id: 15,
        title: 'Final Operation',
        dbType: 'nosql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: FINAL MISSION - Extract the flag.

Find the mission IRON_CURTAIN by codename.

OBJECTIVE: Query for codename = "IRON_CURTAIN".

HINT: db.missions.findOne({codename: "value"})`,
        tables: ['missions'],
        expectedQuery: /db\.missions\.(find|findOne)\s*\(\s*\{.*codename.*IRON_CURTAIN.*\}/i,
        expectedKeywords: ['db', 'missions', 'codename', 'IRON_CURTAIN'],
        queryHint: 'find a specific mission by codename',
        validation: (results) => results.length >= 1 && results[0].codename === 'IRON_CURTAIN',
        successMessage: 'MISSION COMPLETE! You\'ve extracted the final intelligence package!',
        intel: 'FLAG{NOSQL_NINJA} - Intel: weapons_program_details, sleeper_agent_list',
        points: 500
    }
];

// Documentation
const DatabaseDocs = {
    sql: {
        title: 'SQL Quick Reference',
        sections: [
            { title: 'Basic SELECT', content: 'Retrieve data from tables', example: `SELECT * FROM users;\nSELECT column1, column2 FROM table_name;` },
            { title: 'WHERE Clause', content: 'Filter results', example: `SELECT * FROM users WHERE status = 'active';` },
            { title: 'JOIN Tables', content: 'Combine data from multiple tables', example: `SELECT u.username, l.action\nFROM users u\nJOIN access_logs l ON u.id = l.user_id;` },
            { title: 'ORDER BY', content: 'Sort results', example: `SELECT * FROM transactions ORDER BY amount DESC;` },
            { title: 'GROUP BY', content: 'Aggregate data', example: `SELECT user_id, COUNT(*) FROM logs GROUP BY user_id;` },
            { title: 'LIKE', content: 'Pattern matching', example: `SELECT * FROM logs WHERE resource LIKE '%secrets%';` }
        ]
    },
    postgresql: {
        title: 'PostgreSQL Quick Reference',
        sections: [
            { title: 'JSONB Operations', content: 'Query JSON data', example: `SELECT metadata->>'country' FROM threat_intel;` },
            { title: 'Array Operations', content: 'Work with arrays', example: `SELECT * FROM scans WHERE 'CVE-2024-1234' = ANY(vulnerabilities);` },
            { title: 'INET Type', content: 'IP address operations', example: `SELECT * FROM scans WHERE target_ip << '10.0.0.0/8';` }
        ]
    },
    nosql: {
        title: 'MongoDB/NoSQL Quick Reference',
        sections: [
            { title: 'find()', content: 'Query documents', example: `db.agents.find({status: "active"})` },
            { title: 'findOne()', content: 'Get single document', example: `db.agents.findOne({codename: "VIPER"})` },
            { title: 'Comparison Operators', content: 'Filter with operators', example: `db.missions.find({budget: {$gt: 1000000}})` },
            { title: 'Multiple Conditions', content: 'AND queries', example: `db.missions.find({status: "completed", outcome: "success"})` }
        ]
    }
};

// ============================================================
// MAIN GAME CONTROLLER
// ============================================================

class SQLHackerGame {
    constructor() {
        this.currentLevel = 0;
        this.score = 0;
        this.queryExecuted = false;
        this.codeValidated = false;
        this.startTime = null;
        this.timerInterval = null;
        this.hintsUsed = 0;
        this.currentLanguage = 'python';

        this.queryEngine = new QueryEngine(GameDatabase);
        this.codeValidator = new CodeValidator();

        this.init();
    }

    init() {
        this.bindEvents();
        this.loadProgress();
    }

    bindEvents() {
        document.getElementById('start-btn').addEventListener('click', () => this.startGame());

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && document.getElementById('intro-screen').classList.contains('active')) {
                this.startGame();
            }
        });

        document.getElementById('run-query-btn').addEventListener('click', () => this.executeQuery());
        document.getElementById('query-input').addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                this.executeQuery();
            }
        });

        document.getElementById('clear-terminal-btn').addEventListener('click', () => this.clearTerminal());

        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchLanguage(e.target.dataset.lang));
        });

        document.getElementById('validate-code-btn').addEventListener('click', () => this.validateCode());
        document.getElementById('submit-mission-btn').addEventListener('click', () => this.submitMission());
        document.getElementById('hint-btn').addEventListener('click', () => this.showHint());
        document.getElementById('close-results').addEventListener('click', () => this.hideResults());
        document.getElementById('toggle-mission').addEventListener('click', () => this.toggleMission());
        document.getElementById('next-level-btn').addEventListener('click', () => this.nextLevel());
        document.getElementById('restart-btn').addEventListener('click', () => this.restartGame());

        // Auto-indent for code input
        const codeInput = document.getElementById('code-input');
        codeInput.addEventListener('keydown', (e) => this.handleCodeKeydown(e));
    }

    // Handle auto-indentation and tab key in code editor
    handleCodeKeydown(e) {
        const textarea = e.target;
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const value = textarea.value;

        // Handle Tab key - insert 4 spaces
        if (e.key === 'Tab') {
            e.preventDefault();
            const indent = '    '; // 4 spaces

            if (e.shiftKey) {
                // Shift+Tab: Remove indent from current line
                const lineStart = value.lastIndexOf('\n', start - 1) + 1;
                const lineContent = value.substring(lineStart, start);

                if (lineContent.startsWith(indent)) {
                    textarea.value = value.substring(0, lineStart) + value.substring(lineStart + 4);
                    textarea.selectionStart = textarea.selectionEnd = start - 4;
                } else if (lineContent.match(/^[ ]+/)) {
                    // Remove whatever leading spaces exist (up to 4)
                    const spaces = lineContent.match(/^[ ]+/)[0];
                    const removeCount = Math.min(spaces.length, 4);
                    textarea.value = value.substring(0, lineStart) + value.substring(lineStart + removeCount);
                    textarea.selectionStart = textarea.selectionEnd = start - removeCount;
                }
            } else {
                // Tab: Insert indent
                textarea.value = value.substring(0, start) + indent + value.substring(end);
                textarea.selectionStart = textarea.selectionEnd = start + 4;
            }
            return;
        }

        // Handle Enter key - auto-indent
        if (e.key === 'Enter') {
            e.preventDefault();

            // Get current line's indentation
            const lineStart = value.lastIndexOf('\n', start - 1) + 1;
            const lineContent = value.substring(lineStart, start);
            const indentMatch = lineContent.match(/^[ ]*/);
            let indent = indentMatch ? indentMatch[0] : '';

            // Check if we should increase indent (line ends with : for Python, { for Go/JS)
            const trimmedLine = lineContent.trim();
            const lastChar = trimmedLine.slice(-1);

            if (this.currentLanguage === 'python') {
                // Python: increase indent after colon
                if (lastChar === ':') {
                    indent += '    ';
                }
            } else if (this.currentLanguage === 'go') {
                // Go: increase indent after opening brace
                if (lastChar === '{') {
                    indent += '    ';
                }
            }

            // Insert newline with proper indentation
            textarea.value = value.substring(0, start) + '\n' + indent + value.substring(end);
            textarea.selectionStart = textarea.selectionEnd = start + 1 + indent.length;

            // Trigger input event for any listeners
            textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }

        // Handle Backspace - remove 4 spaces if at indent boundary
        if (e.key === 'Backspace' && start === end) {
            const lineStart = value.lastIndexOf('\n', start - 1) + 1;
            const beforeCursor = value.substring(lineStart, start);

            // If cursor is right after spaces and those spaces are a multiple of 4
            if (beforeCursor.length > 0 && beforeCursor.match(/^[ ]+$/) && beforeCursor.length % 4 === 0) {
                e.preventDefault();
                const removeCount = 4;
                textarea.value = value.substring(0, start - removeCount) + value.substring(end);
                textarea.selectionStart = textarea.selectionEnd = start - removeCount;
            }
        }

        // Handle closing brace/bracket - auto dedent for Go
        if (this.currentLanguage === 'go' && (e.key === '}' || e.key === ')')) {
            const lineStart = value.lastIndexOf('\n', start - 1) + 1;
            const beforeCursor = value.substring(lineStart, start);

            // If line only has whitespace before cursor, reduce indent
            if (beforeCursor.match(/^[ ]+$/) && beforeCursor.length >= 4) {
                e.preventDefault();
                const newIndent = beforeCursor.substring(4);
                textarea.value = value.substring(0, lineStart) + newIndent + e.key + value.substring(end);
                textarea.selectionStart = textarea.selectionEnd = lineStart + newIndent.length + 1;
            }
        }
    }

    startGame() {
        document.getElementById('intro-screen').classList.remove('active');
        document.getElementById('game-screen').classList.add('active');
        this.loadLevel(this.currentLevel);
        this.startTimer();
    }

    loadLevel(levelIndex) {
        if (levelIndex >= GameLevels.length) {
            this.showGameComplete();
            return;
        }

        const level = GameLevels[levelIndex];
        this.currentLevel = levelIndex;
        this.queryExecuted = false;
        this.codeValidated = false;
        this.hintsUsed = 0;

        document.getElementById('current-level').textContent = levelIndex + 1;
        document.getElementById('db-type-indicator').textContent = level.dbType.toUpperCase();
        document.getElementById('mission-text').textContent = level.briefing;

        this.queryEngine.setDbType(level.dbType);

        const prompts = { sql: 'SQL>', postgresql: 'PSQL>', nosql: 'MongoDB>' };
        document.getElementById('db-prompt').textContent = prompts[level.dbType];

        this.loadSchema(level);
        this.loadDocs(level.dbType);
        this.updateCodeTemplate(level);

        document.getElementById('hint-text').textContent = '';
        document.getElementById('hint-text').classList.add('hidden');
        document.getElementById('hint-btn').disabled = false;

        this.clearTerminal();
        this.addTerminalLine(`[SYSTEM] Connected to ${level.dbType.toUpperCase()} database...`, 'system');
        this.addTerminalLine(`[SYSTEM] Mission ${levelIndex + 1}: ${level.title}`, 'system');
        this.addTerminalLine(`[SYSTEM] Difficulty: ${level.difficulty.toUpperCase()}`, 'system');
        this.addTerminalLine(`[SYSTEM] Awaiting query input...`, 'system');

        document.getElementById('code-input').value = '';
        this.saveProgress();
    }

    loadSchema(level) {
        const schemaContent = document.getElementById('schema-content');
        schemaContent.innerHTML = '';

        const dbType = level.dbType === 'nosql' ? 'nosql' : (level.dbType === 'postgresql' ? 'postgresql' : 'sql');
        const tables = level.tables || Object.keys(GameDatabase[dbType] || GameDatabase.sql);

        for (const tableName of tables) {
            let tableData;
            if (dbType === 'nosql') {
                tableData = GameDatabase.nosql[tableName];
            } else if (dbType === 'postgresql') {
                tableData = GameDatabase.postgresql[tableName] || GameDatabase.sql[tableName];
            } else {
                tableData = GameDatabase.sql[tableName];
            }

            if (!tableData) continue;

            const tableEl = document.createElement('div');
            tableEl.className = 'schema-table';

            const nameEl = document.createElement('div');
            nameEl.className = 'schema-table-name';
            nameEl.textContent = dbType === 'nosql' ? `Collection: ${tableName}` : `Table: ${tableName}`;
            tableEl.appendChild(nameEl);

            const columnsEl = document.createElement('div');
            columnsEl.className = 'schema-columns';

            if (dbType === 'nosql') {
                const sampleDoc = tableData.data[0];
                if (sampleDoc) {
                    for (const [key, value] of Object.entries(sampleDoc)) {
                        const colEl = document.createElement('div');
                        colEl.className = 'schema-column';
                        colEl.innerHTML = `<span class="column-name">${key}</span><span class="column-type">${this.getValueType(value)}</span>`;
                        columnsEl.appendChild(colEl);
                    }
                }
            } else {
                for (const col of tableData.columns) {
                    const colEl = document.createElement('div');
                    colEl.className = 'schema-column';
                    let nameHtml = `<span class="column-name">${col.name}${col.key ? `<span class="column-key">${col.key}</span>` : ''}</span>`;
                    colEl.innerHTML = `${nameHtml}<span class="column-type">${col.type}</span>`;
                    columnsEl.appendChild(colEl);
                }
            }

            tableEl.appendChild(columnsEl);
            schemaContent.appendChild(tableEl);
        }
    }

    getValueType(value) {
        if (value === null) return 'null';
        if (Array.isArray(value)) return 'Array';
        if (typeof value === 'object') return 'Object';
        return typeof value;
    }

    loadDocs(dbType) {
        const docsContent = document.getElementById('docs-content');
        const docs = DatabaseDocs[dbType] || DatabaseDocs.sql;

        docsContent.innerHTML = `<h2>${docs.title}</h2>`;

        for (const section of docs.sections) {
            const sectionEl = document.createElement('div');
            sectionEl.className = 'docs-section';
            sectionEl.innerHTML = `<h3>${section.title}</h3><p>${section.content}</p><pre>${this.escapeHtml(section.example)}</pre>`;
            docsContent.appendChild(sectionEl);
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateCodeTemplate(level) {
        const template = this.codeValidator.getTemplate(level, this.currentLanguage);
        document.getElementById('code-template-content').textContent = template;
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `${tabName}-tab`);
        });
    }

    switchLanguage(lang) {
        this.currentLanguage = lang;
        this.codeValidator.setLanguage(lang);

        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.lang === lang);
        });

        const level = GameLevels[this.currentLevel];
        this.updateCodeTemplate(level);
    }

    executeQuery() {
        const queryInput = document.getElementById('query-input');
        const query = queryInput.value.trim();

        if (!query) {
            this.addTerminalLine('[ERROR] No query provided.', 'error');
            return;
        }

        this.addTerminalLine(query, 'input');

        const result = this.queryEngine.execute(query);

        if (result.success) {
            this.displayResults(result);
            this.addTerminalLine(`[SUCCESS] Query executed. ${result.rowCount} row(s) returned.`, 'success');

            const level = GameLevels[this.currentLevel];
            if (level.validation(result.data)) {
                this.queryExecuted = true;
                this.addTerminalLine('[SYSTEM] Query matches mission objective!', 'system');
            }
        } else {
            this.addTerminalLine(`[ERROR] ${result.error}`, 'error');
        }
    }

    displayResults(result) {
        const panel = document.getElementById('results-panel');
        const thead = document.getElementById('results-thead');
        const tbody = document.getElementById('results-tbody');

        thead.innerHTML = '';
        tbody.innerHTML = '';

        if (result.data.length === 0) {
            panel.classList.remove('hidden');
            return;
        }

        const firstDoc = result.data[0];
        const columns = result.columns || Object.keys(firstDoc);

        const headerRow = document.createElement('tr');
        columns.forEach(col => {
            const th = document.createElement('th');
            th.textContent = col;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);

        result.data.forEach(row => {
            const tr = document.createElement('tr');
            columns.forEach(col => {
                const td = document.createElement('td');
                const value = row[col];
                td.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });

        panel.classList.remove('hidden');
    }

    hideResults() {
        document.getElementById('results-panel').classList.add('hidden');
    }

    addTerminalLine(text, type = 'output') {
        const output = document.getElementById('terminal-output');
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    clearTerminal() {
        document.getElementById('terminal-output').innerHTML = '';
    }

    validateCode() {
        const code = document.getElementById('code-input').value;
        const level = GameLevels[this.currentLevel];

        const validation = this.codeValidator.validate(code, level, this.currentLanguage);

        if (validation.passed) {
            this.codeValidated = true;
            this.addTerminalLine('[CODE] Validation PASSED!', 'success');
            validation.warnings.forEach(w => this.addTerminalLine(`[WARNING] ${w}`, 'error'));
        } else {
            this.addTerminalLine('[CODE] Validation FAILED:', 'error');
            validation.errors.forEach(e => this.addTerminalLine(`  - ${e}`, 'error'));
        }
    }

    submitMission() {
        if (!this.queryExecuted) {
            this.addTerminalLine('[SYSTEM] Query objective not completed! Execute the correct query first.', 'error');
            return;
        }

        if (!this.codeValidated) {
            this.addTerminalLine('[SYSTEM] Code not validated! Validate your implementation first.', 'error');
            return;
        }

        const level = GameLevels[this.currentLevel];
        let levelScore = level.points;

        const elapsed = Date.now() - this.startTime;
        const timeBonus = Math.max(0, Math.floor(100 - (elapsed / 1000 / 60) * 25));
        levelScore += timeBonus;

        levelScore -= this.hintsUsed * 50;
        levelScore = Math.max(levelScore, 50);

        this.score += levelScore;
        document.getElementById('score').textContent = this.score;

        this.showLevelComplete(levelScore, timeBonus, level);
    }

    showLevelComplete(levelScore, timeBonus, level) {
        document.getElementById('stat-query').textContent = '100%';
        document.getElementById('stat-code').textContent = 'PASSED';
        document.getElementById('stat-time').textContent = `+${timeBonus}`;
        document.getElementById('stat-level-score').textContent = levelScore;
        document.getElementById('intel-data').textContent = level.intel;

        document.getElementById('level-complete-modal').classList.remove('hidden');
        this.addTerminalLine(`[SYSTEM] ${level.successMessage}`, 'success');
    }

    nextLevel() {
        document.getElementById('level-complete-modal').classList.add('hidden');
        this.hideResults();
        this.loadLevel(this.currentLevel + 1);
        this.startTime = Date.now();
    }

    showHint() {
        const level = GameLevels[this.currentLevel];
        this.hintsUsed++;

        let hint = '';
        if (this.hintsUsed === 1) {
            hint = level.queryHint ? `Your query should ${level.queryHint}.` : 'Check the DOCS tab for syntax help.';
        } else if (this.hintsUsed === 2) {
            hint = `Expected keywords: ${level.expectedKeywords.join(', ')}`;
        } else {
            hint = this.codeValidator.getHint(level, this.currentLanguage, this.hintsUsed);
        }

        document.getElementById('hint-text').textContent = `HINT ${this.hintsUsed}: ${hint}`;
        document.getElementById('hint-text').classList.remove('hidden');
        this.addTerminalLine(`[SYSTEM] Hint revealed (-50 points)`, 'system');

        if (this.hintsUsed >= 3) {
            document.getElementById('hint-btn').disabled = true;
        }
    }

    toggleMission() {
        const content = document.getElementById('mission-content');
        const btn = document.getElementById('toggle-mission');

        if (content.style.display === 'none') {
            content.style.display = 'block';
            btn.textContent = '[-]';
        } else {
            content.style.display = 'none';
            btn.textContent = '[+]';
        }
    }

    startTimer() {
        this.startTime = Date.now();

        if (this.timerInterval) {
            clearInterval(this.timerInterval);
        }

        this.timerInterval = setInterval(() => {
            const elapsed = Date.now() - this.startTime;
            const minutes = Math.floor(elapsed / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            document.getElementById('timer').textContent =
                `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }, 1000);
    }

    showGameComplete() {
        clearInterval(this.timerInterval);

        document.getElementById('final-score').textContent = this.score;
        document.getElementById('missions-completed').textContent = GameLevels.length;

        const maxScore = GameLevels.reduce((sum, l) => sum + l.points + 100, 0);
        const percentage = this.score / maxScore;

        let rank;
        if (percentage >= 0.9) rank = 'ELITE HACKER';
        else if (percentage >= 0.75) rank = 'SENIOR OPERATIVE';
        else if (percentage >= 0.5) rank = 'FIELD AGENT';
        else if (percentage >= 0.25) rank = 'JUNIOR ANALYST';
        else rank = 'RECRUIT';

        document.getElementById('final-rank').textContent = rank;
        document.getElementById('game-complete-modal').classList.remove('hidden');

        localStorage.removeItem('sqlhacker_progress');
    }

    restartGame() {
        document.getElementById('game-complete-modal').classList.add('hidden');
        this.currentLevel = 0;
        this.score = 0;
        document.getElementById('score').textContent = '0';
        this.loadLevel(0);
        this.startTimer();
    }

    saveProgress() {
        const progress = { level: this.currentLevel, score: this.score };
        localStorage.setItem('sqlhacker_progress', JSON.stringify(progress));
    }

    loadProgress() {
        const saved = localStorage.getItem('sqlhacker_progress');
        if (saved) {
            const progress = JSON.parse(saved);
            this.currentLevel = progress.level || 0;
            this.score = progress.score || 0;
            document.getElementById('score').textContent = this.score;
        }
    }
}

// Initialize game when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.game = new SQLHackerGame();
});
