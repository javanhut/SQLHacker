// SQL_HACK3R - Fake Database Engine
// Contains all the fake data for the game

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

    // PostgreSQL specific tables (with array and JSON types)
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

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GameDatabase;
}
