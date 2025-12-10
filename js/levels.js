// SQL_HACK3R - Game Levels
// Contains all mission definitions and objectives

const GameLevels = [
    // ============ SQL BASICS (Levels 1-4) ============
    {
        id: 1,
        title: 'First Contact',
        dbType: 'sql',
        difficulty: 'beginner',
        briefing: `MISSION BRIEFING: Welcome to your first operation, recruit.

We've gained access to CorpSec's employee database. Your objective is simple: retrieve a list of all users in the system.

This will help us identify potential targets for further reconnaissance.

OBJECTIVE: Select all columns from the 'users' table.

HINT: Use SELECT * FROM table_name to retrieve all data.`,
        tables: ['users'],
        expectedQuery: /SELECT\s+\*\s+FROM\s+users/i,
        expectedKeywords: ['SELECT', 'FROM', 'users'],
        targetData: 'users',
        queryHint: 'select all columns from the users table',
        validation: (results) => {
            return results.length === 7 && results[0].username !== undefined;
        },
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

Intelligence suggests there's a user with suspicious activity. Find all users whose status is marked as 'suspicious'.

OBJECTIVE: Select all users where status equals 'suspicious'.

HINT: Use WHERE clause to filter: WHERE column = 'value'`,
        tables: ['users'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+users\s+WHERE\s+status\s*=\s*['"]suspicious['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'users', 'WHERE', 'status'],
        queryHint: 'filter users by status',
        validation: (results) => {
            return results.length === 1 && results[0].username === 'ghost_user';
        },
        successMessage: 'Target acquired! The ghost_user account is confirmed suspicious. Let\'s dig deeper.',
        intel: 'Suspicious user identified: ghost_user (ID: 4). Email: shadow@darknet.onion',
        points: 150
    },
    {
        id: 3,
        title: 'Access Trail',
        dbType: 'sql',
        difficulty: 'beginner',
        briefing: `MISSION BRIEFING: Now we need to trace the ghost_user's activities.

Access the access_logs table and find all entries for user_id 4 (ghost_user).

OBJECTIVE: Retrieve all access logs for user_id = 4.

HINT: The access_logs table links to users via user_id.`,
        tables: ['users', 'access_logs'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+access_logs\s+WHERE\s+user_id\s*=\s*4/i,
        expectedKeywords: ['SELECT', 'FROM', 'access_logs', 'WHERE', 'user_id'],
        queryHint: 'filter access_logs by user_id',
        validation: (results) => {
            return results.length >= 4 && results.every(r => r.user_id === 4);
        },
        successMessage: 'Critical intelligence obtained! Ghost_user has been downloading classified files and uploading backdoors!',
        intel: 'ghost_user activities: LOGIN, DOWNLOAD (classified.zip), DELETE attempt, UPLOAD (backdoor.sh)',
        points: 150
    },
    {
        id: 4,
        title: 'Joining Forces',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: We need the full picture.

Combine the users and access_logs tables to see usernames alongside their actions. Focus on actions related to the '/secrets/' path.

OBJECTIVE: JOIN users and access_logs tables, filter for resources containing '/secrets/'.

HINT: Use JOIN ... ON and LIKE '%pattern%' for partial matching.`,
        tables: ['users', 'access_logs'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+(users|access_logs)\s+(INNER\s+)?JOIN\s+(users|access_logs)\s+ON\s+.+WHERE\s+.+LIKE\s+['"]%.*secrets.*%['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'JOIN', 'ON', 'WHERE', 'LIKE', 'secrets'],
        queryHint: 'join users with access_logs and filter by resource path',
        validation: (results) => {
            return results.length >= 1 && results.some(r => r.resource?.includes('/secrets/'));
        },
        successMessage: 'Connection established! We now know exactly who accessed the classified files.',
        intel: 'ghost_user downloaded /secrets/classified.zip at 03:35:00',
        points: 200
    },

    // ============ SQL INTERMEDIATE (Levels 5-7) ============
    {
        id: 5,
        title: 'Money Trail',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Follow the money.

Suspicious transactions have been detected. Find all transactions over $100,000 ordered by amount descending.

OBJECTIVE: Select from transactions where amount > 100000, ordered by amount DESC.

HINT: Use comparison operators and ORDER BY column DESC.`,
        tables: ['transactions'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+transactions\s+WHERE\s+amount\s*>\s*100000.*ORDER\s+BY\s+amount\s+DESC/i,
        expectedKeywords: ['SELECT', 'FROM', 'transactions', 'WHERE', 'amount', 'ORDER BY', 'DESC'],
        queryHint: 'filter transactions by amount and order descending',
        validation: (results) => {
            return results.length >= 2 && results[0].amount >= results[results.length - 1].amount;
        },
        successMessage: 'Financial trail uncovered! Large sums moving to offshore accounts detected.',
        intel: 'Suspicious transfers: $175,000 to ACC-888-SHELL, then $174,500 to ACC-777-CAYMAN',
        points: 200
    },
    {
        id: 6,
        title: 'Aggregate Intelligence',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: We need statistical analysis.

Count how many access log entries exist for each user_id to identify the most active accounts.

OBJECTIVE: Use COUNT and GROUP BY to aggregate access_logs by user_id.

HINT: SELECT column, COUNT(*) FROM table GROUP BY column`,
        tables: ['access_logs'],
        expectedQuery: /SELECT\s+.*(user_id|COUNT).*\s+FROM\s+access_logs\s+.*GROUP\s+BY\s+user_id/i,
        expectedKeywords: ['SELECT', 'COUNT', 'FROM', 'access_logs', 'GROUP BY', 'user_id'],
        queryHint: 'group access_logs by user_id and count entries',
        validation: (results) => {
            return results.length >= 3 && results.some(r => r['COUNT(*)'] !== undefined || r.count !== undefined);
        },
        successMessage: 'Pattern analysis complete! Ghost_user has the most suspicious activity.',
        intel: 'Activity count by user: ghost_user leads with 5 logged actions, all during off-hours',
        points: 250
    },
    {
        id: 7,
        title: 'The Vault',
        dbType: 'sql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Penetrate the credentials vault.

Find credentials for the server with classification 'top_secret'. You'll need to join credentials with servers.

OBJECTIVE: Join credentials and servers tables, filter for top_secret classification.

HINT: Look for the foreign key relationship between the tables.`,
        tables: ['credentials', 'servers'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+(credentials|servers)\s+(INNER\s+)?JOIN\s+(credentials|servers)\s+ON\s+.+WHERE\s+.*classification\s*=\s*['"]top_secret['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'JOIN', 'ON', 'WHERE', 'classification', 'top_secret'],
        queryHint: 'join credentials with servers and filter by classification',
        validation: (results) => {
            return results.length >= 1 && results.some(r =>
                r.encrypted_password?.includes('FLAG{SQL_MASTER}') ||
                r.service_name === 'VaultAPI'
            );
        },
        successMessage: 'VAULT BREACHED! You\'ve found credentials for the secret vault server!',
        intel: 'FLAG{SQL_MASTER} - VaultAPI credentials obtained for secret-vault server',
        points: 300
    },

    // ============ POSTGRESQL LEVELS (8-11) ============
    {
        id: 8,
        title: 'Network Recon',
        dbType: 'postgresql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Switching to PostgreSQL analytics database.

Access the network_scans table to find all hosts with risk_score above 8.0. These are critical vulnerabilities.

OBJECTIVE: Query network_scans for high-risk systems (risk_score > 8.0).

HINT: PostgreSQL uses similar syntax to standard SQL.`,
        tables: ['network_scans'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+network_scans\s+WHERE\s+risk_score\s*>\s*8/i,
        expectedKeywords: ['SELECT', 'FROM', 'network_scans', 'WHERE', 'risk_score'],
        queryHint: 'filter network_scans by risk_score',
        validation: (results) => {
            return results.length >= 1 && results.every(r => r.risk_score > 8.0);
        },
        successMessage: 'Critical vulnerabilities identified! Legacy systems are severely compromised.',
        intel: '2 critical systems: legacy-app (9.8) with MS17-010, honeypot-01 (10.0) with BACKDOOR-DETECTED',
        points: 250
    },
    {
        id: 9,
        title: 'Threat Intel',
        dbType: 'postgresql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Analyze the threat intelligence database.

Find all threat indicators associated with 'APT-SHADOW' using PostgreSQL's JSONB features. The metadata field contains additional intel.

OBJECTIVE: Query threat_intel for APT-SHADOW indicators.

HINT: You can access JSONB fields directly in WHERE clauses.`,
        tables: ['threat_intel'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+threat_intel\s+WHERE\s+threat_actor\s*=\s*['"]APT-SHADOW['"]/i,
        expectedKeywords: ['SELECT', 'FROM', 'threat_intel', 'WHERE', 'threat_actor', 'APT-SHADOW'],
        queryHint: 'filter threat_intel by threat_actor',
        validation: (results) => {
            return results.length >= 3 && results.every(r => r.threat_actor === 'APT-SHADOW');
        },
        successMessage: 'Threat actor profile compiled! APT-SHADOW is linked to the breach.',
        intel: 'APT-SHADOW indicators: IP 185.234.72.19 (Russia), domain evil-domain.tk, email shadow@darknet.onion',
        points: 300
    },
    {
        id: 10,
        title: 'The Breach Timeline',
        dbType: 'postgresql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Reconstruct the breach timeline.

Query the audit_events table to find all events by 'ghost_user' ordered by timestamp. The details JSONB field contains critical information.

OBJECTIVE: Get all audit events for ghost_user, ordered chronologically.

HINT: ORDER BY event_time to see the sequence of events.`,
        tables: ['audit_events'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+audit_events\s+WHERE\s+actor\s*=\s*['"]ghost_user['"].*ORDER\s+BY\s+event_time/i,
        expectedKeywords: ['SELECT', 'FROM', 'audit_events', 'WHERE', 'actor', 'ghost_user', 'ORDER BY'],
        queryHint: 'filter audit_events by actor and order by time',
        validation: (results) => {
            return results.length >= 5 && results.every(r => r.actor === 'ghost_user');
        },
        successMessage: 'Breach timeline reconstructed! Full attack sequence documented.',
        intel: 'Attack sequence: auth -> privilege_escalation -> data_exfiltration -> log_tampering -> backdoor_install',
        points: 350
    },
    {
        id: 11,
        title: 'Vulnerability Analysis',
        dbType: 'postgresql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Deep analysis required.

Find network scan results where the vulnerabilities array contains 'BACKDOOR-DETECTED'. Use PostgreSQL array operations.

OBJECTIVE: Query for scans with backdoor vulnerabilities.

HINT: Use ANY() or @> operator for array searching in PostgreSQL.`,
        tables: ['network_scans'],
        expectedQuery: /SELECT\s+.+\s+FROM\s+network_scans\s+WHERE\s+.*('BACKDOOR-DETECTED'\s*=\s*ANY|vulnerabilities\s*@>|BACKDOOR)/i,
        expectedKeywords: ['SELECT', 'FROM', 'network_scans', 'WHERE', 'BACKDOOR'],
        queryHint: 'search for backdoor in vulnerabilities array',
        validation: (results) => {
            return results.length >= 1 && results.some(r =>
                r.vulnerabilities?.includes('BACKDOOR-DETECTED')
            );
        },
        successMessage: 'Backdoor confirmed! The honeypot has been compromised - or is it bait?',
        intel: 'BACKDOOR-DETECTED on 10.0.0.99 (honeypot-01) - 7 open ports, multiple vulnerable services',
        points: 350
    },

    // ============ NOSQL LEVELS (12-15) ============
    {
        id: 12,
        title: 'Agent Files',
        dbType: 'nosql',
        difficulty: 'intermediate',
        briefing: `MISSION BRIEFING: Switching to NoSQL operations database.

Access the agents collection and find all active agents. Document databases use different query syntax.

OBJECTIVE: Use db.agents.find() to query for status = "active".

HINT: db.collection.find({field: "value"})`,
        tables: ['agents'],
        expectedQuery: /db\.agents\.find\s*\(\s*\{.*status.*active.*\}/i,
        expectedKeywords: ['db', 'agents', 'find', 'status', 'active'],
        queryHint: 'find documents where status equals active',
        validation: (results) => {
            return results.length >= 3 && results.every(r => r.status === 'active');
        },
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

Find all completed missions that resulted in 'success'. We need to understand past operation patterns.

OBJECTIVE: Query missions collection for status="completed" AND outcome="success".

HINT: Use multiple conditions in your query: {field1: "val1", field2: "val2"}`,
        tables: ['missions'],
        expectedQuery: /db\.missions\.find\s*\(\s*\{.*status.*completed.*outcome.*success|outcome.*success.*status.*completed.*\}/i,
        expectedKeywords: ['db', 'missions', 'find', 'status', 'completed', 'outcome', 'success'],
        queryHint: 'find missions with multiple conditions',
        validation: (results) => {
            return results.length >= 2 && results.every(r =>
                r.status === 'completed' && r.outcome === 'success'
            );
        },
        successMessage: 'Mission archives decrypted! Historical operations revealed.',
        intel: 'Successful missions: DARK_HARVEST (financial data), IRON_CURTAIN (defector extraction)',
        points: 300
    },
    {
        id: 14,
        title: 'Intercepted Communications',
        dbType: 'nosql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: Critical intercepts require analysis.

Query intercepted_comms for messages with priority "critical". These are high-value intelligence items.

OBJECTIVE: Find all communications with priority = "critical".

HINT: NoSQL queries match exact field values unless using operators.`,
        tables: ['intercepted_comms'],
        expectedQuery: /db\.intercepted_comms\.find\s*\(\s*\{.*priority.*critical.*\}/i,
        expectedKeywords: ['db', 'intercepted_comms', 'find', 'priority', 'critical'],
        queryHint: 'find communications by priority level',
        validation: (results) => {
            return results.length >= 2 && results.every(r => r.priority === 'critical');
        },
        successMessage: 'Critical intercepts obtained! Zero-day exploit and insider threat detected!',
        intel: 'CRITICAL: Zero-day for industrial control systems ready. Insider uploading employee database.',
        points: 350
    },
    {
        id: 15,
        title: 'Final Operation',
        dbType: 'nosql',
        difficulty: 'advanced',
        briefing: `MISSION BRIEFING: FINAL MISSION - Extract the flag.

One of our completed missions contains a hidden flag in the intel_gathered array. Find the mission IRON_CURTAIN and extract its intelligence.

OBJECTIVE: Query for the IRON_CURTAIN mission by codename.

HINT: db.missions.findOne({codename: "value"})`,
        tables: ['missions'],
        expectedQuery: /db\.missions\.(find|findOne)\s*\(\s*\{.*codename.*IRON_CURTAIN.*\}/i,
        expectedKeywords: ['db', 'missions', 'codename', 'IRON_CURTAIN'],
        queryHint: 'find a specific mission by codename',
        validation: (results) => {
            return results.length >= 1 && results[0].codename === 'IRON_CURTAIN';
        },
        successMessage: 'MISSION COMPLETE! You\'ve extracted the final intelligence package!',
        intel: 'FLAG{NOSQL_NINJA} - Intel package: weapons_program_details, sleeper_agent_list',
        points: 500
    }
];

// Documentation for each database type
const DatabaseDocs = {
    sql: {
        title: 'SQL Quick Reference',
        sections: [
            {
                title: 'Basic SELECT',
                content: 'Retrieve data from tables',
                example: `SELECT column1, column2 FROM table_name;
SELECT * FROM users;`
            },
            {
                title: 'WHERE Clause',
                content: 'Filter results based on conditions',
                example: `SELECT * FROM users WHERE status = 'active';
SELECT * FROM logs WHERE user_id = 4;`
            },
            {
                title: 'JOIN Tables',
                content: 'Combine data from multiple tables',
                example: `SELECT u.username, l.action
FROM users u
JOIN access_logs l ON u.id = l.user_id;`
            },
            {
                title: 'ORDER BY',
                content: 'Sort results',
                example: `SELECT * FROM transactions
ORDER BY amount DESC;`
            },
            {
                title: 'GROUP BY & Aggregates',
                content: 'Group and summarize data',
                example: `SELECT user_id, COUNT(*) as total
FROM access_logs
GROUP BY user_id;`
            },
            {
                title: 'LIKE Pattern Matching',
                content: 'Match patterns in text',
                example: `SELECT * FROM logs
WHERE resource LIKE '%secrets%';`
            }
        ]
    },

    postgresql: {
        title: 'PostgreSQL Quick Reference',
        sections: [
            {
                title: 'JSONB Operations',
                content: 'Query JSON data',
                example: `-- Get JSON field
SELECT metadata->>'country' FROM threat_intel;

-- Filter by JSON field
SELECT * FROM audit_events
WHERE details->>'mfa_bypassed' = 'true';`
            },
            {
                title: 'Array Operations',
                content: 'Work with array columns',
                example: `-- Check if value in array
SELECT * FROM network_scans
WHERE 'CVE-2024-1234' = ANY(vulnerabilities);

-- Array contains
SELECT * FROM scans
WHERE open_ports @> ARRAY[22, 80];`
            },
            {
                title: 'INET Type',
                content: 'IP address operations',
                example: `SELECT * FROM network_scans
WHERE target_ip << '10.0.0.0/8';`
            },
            {
                title: 'Timestamp Operations',
                content: 'Date/time functions',
                example: `SELECT * FROM audit_events
WHERE event_time > NOW() - INTERVAL '24 hours';`
            }
        ]
    },

    nosql: {
        title: 'MongoDB/NoSQL Quick Reference',
        sections: [
            {
                title: 'find()',
                content: 'Query documents',
                example: `// Find all matching documents
db.agents.find({status: "active"})

// Multiple conditions
db.missions.find({status: "completed", outcome: "success"})`
            },
            {
                title: 'findOne()',
                content: 'Get single document',
                example: `db.agents.findOne({codename: "VIPER"})`
            },
            {
                title: 'Comparison Operators',
                content: 'Filter with operators',
                example: `// Greater than
db.missions.find({budget: {$gt: 1000000}})

// In array of values
db.agents.find({status: {$in: ["active", "standby"]}})`
            },
            {
                title: 'Nested Fields',
                content: 'Query nested documents',
                example: `db.agents.find({"current_location.country": "Germany"})`
            },
            {
                title: 'Array Queries',
                content: 'Query array fields',
                example: `// Array contains value
db.agents.find({specialization: "cyber_ops"})

// Array element match
db.missions.find({assigned_agents: {$elemMatch: {$eq: "agent_002"}}})`
            },
            {
                title: 'Aggregation',
                content: 'Complex data processing',
                example: `db.missions.aggregate([
    {$match: {status: "completed"}},
    {$group: {_id: "$outcome", count: {$sum: 1}}}
])`
            }
        ]
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { GameLevels, DatabaseDocs };
}
