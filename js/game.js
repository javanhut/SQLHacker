// SQL_HACK3R - Main Game Controller

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
        // Start button
        document.getElementById('start-btn').addEventListener('click', () => this.startGame());

        // Enter key on intro screen
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && document.getElementById('intro-screen').classList.contains('active')) {
                this.startGame();
            }
        });

        // Query execution
        document.getElementById('run-query-btn').addEventListener('click', () => this.executeQuery());
        document.getElementById('query-input').addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                this.executeQuery();
            }
        });

        // Clear terminal
        document.getElementById('clear-terminal-btn').addEventListener('click', () => this.clearTerminal());

        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Language switching
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchLanguage(e.target.dataset.lang));
        });

        // Code validation
        document.getElementById('validate-code-btn').addEventListener('click', () => this.validateCode());

        // Mission submission
        document.getElementById('submit-mission-btn').addEventListener('click', () => this.submitMission());

        // Hints
        document.getElementById('hint-btn').addEventListener('click', () => this.showHint());

        // Results panel
        document.getElementById('close-results').addEventListener('click', () => this.hideResults());

        // Mission panel toggle
        document.getElementById('toggle-mission').addEventListener('click', () => this.toggleMission());

        // Modal buttons
        document.getElementById('next-level-btn').addEventListener('click', () => this.nextLevel());
        document.getElementById('restart-btn').addEventListener('click', () => this.restartGame());
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

        // Update UI
        document.getElementById('current-level').textContent = levelIndex + 1;
        document.getElementById('db-type-indicator').textContent = level.dbType.toUpperCase();
        document.getElementById('mission-text').textContent = level.briefing;

        // Set database type
        this.queryEngine.setDbType(level.dbType);

        // Update prompt
        const prompts = {
            sql: 'SQL>',
            postgresql: 'PSQL>',
            nosql: 'MongoDB>'
        };
        document.getElementById('db-prompt').textContent = prompts[level.dbType];

        // Load schema
        this.loadSchema(level);

        // Load documentation
        this.loadDocs(level.dbType);

        // Update code template
        this.updateCodeTemplate(level);

        // Reset hints
        document.getElementById('hint-text').textContent = '';
        document.getElementById('hint-text').classList.add('hidden');
        document.getElementById('hint-btn').disabled = false;

        // Clear terminal output but keep system messages
        this.clearTerminal();
        this.addTerminalLine(`[SYSTEM] Connected to ${level.dbType.toUpperCase()} database...`, 'system');
        this.addTerminalLine(`[SYSTEM] Mission ${levelIndex + 1}: ${level.title}`, 'system');
        this.addTerminalLine(`[SYSTEM] Difficulty: ${level.difficulty.toUpperCase()}`, 'system');
        this.addTerminalLine(`[SYSTEM] Awaiting query input...`, 'system');

        // Clear code input
        document.getElementById('code-input').value = '';

        // Save progress
        this.saveProgress();
    }

    loadSchema(level) {
        const schemaContent = document.getElementById('schema-content');
        schemaContent.innerHTML = '';

        const dbType = level.dbType === 'nosql' ? 'nosql' :
            (level.dbType === 'postgresql' ? 'postgresql' : 'sql');

        // Get relevant tables/collections
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
                // Show document structure for NoSQL
                const sampleDoc = tableData.data[0];
                if (sampleDoc) {
                    for (const [key, value] of Object.entries(sampleDoc)) {
                        const colEl = document.createElement('div');
                        colEl.className = 'schema-column';

                        const colName = document.createElement('span');
                        colName.className = 'column-name';
                        colName.textContent = key;

                        const colType = document.createElement('span');
                        colType.className = 'column-type';
                        colType.textContent = this.getValueType(value);

                        colEl.appendChild(colName);
                        colEl.appendChild(colType);
                        columnsEl.appendChild(colEl);
                    }
                }
            } else {
                // Show columns for SQL
                for (const col of tableData.columns) {
                    const colEl = document.createElement('div');
                    colEl.className = 'schema-column';

                    const colName = document.createElement('span');
                    colName.className = 'column-name';
                    colName.textContent = col.name;
                    if (col.key) {
                        const keyBadge = document.createElement('span');
                        keyBadge.className = 'column-key';
                        keyBadge.textContent = col.key;
                        colName.appendChild(keyBadge);
                    }

                    const colType = document.createElement('span');
                    colType.className = 'column-type';
                    colType.textContent = col.type;

                    colEl.appendChild(colName);
                    colEl.appendChild(colType);
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

            sectionEl.innerHTML = `
                <h3>${section.title}</h3>
                <p>${section.content}</p>
                <pre>${this.escapeHtml(section.example)}</pre>
            `;

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

        // Update template
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

            // Check if query matches expected
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

        if (result.type === 'nosql') {
            // Display NoSQL results
            const firstDoc = result.data[0];
            if (firstDoc) {
                const columns = Object.keys(firstDoc);
                const headerRow = document.createElement('tr');
                columns.forEach(col => {
                    const th = document.createElement('th');
                    th.textContent = col;
                    headerRow.appendChild(th);
                });
                thead.appendChild(headerRow);

                result.data.forEach(doc => {
                    const row = document.createElement('tr');
                    columns.forEach(col => {
                        const td = document.createElement('td');
                        const value = doc[col];
                        td.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
                        row.appendChild(td);
                    });
                    tbody.appendChild(row);
                });
            }
        } else {
            // Display SQL results
            if (result.columns) {
                const headerRow = document.createElement('tr');
                result.columns.forEach(col => {
                    const th = document.createElement('th');
                    th.textContent = col;
                    headerRow.appendChild(th);
                });
                thead.appendChild(headerRow);
            }

            result.data.forEach(row => {
                const tr = document.createElement('tr');
                if (result.columns) {
                    result.columns.forEach(col => {
                        const td = document.createElement('td');
                        const value = row[col];
                        td.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
                        tr.appendChild(td);
                    });
                } else {
                    Object.values(row).forEach(value => {
                        const td = document.createElement('td');
                        td.textContent = typeof value === 'object' ? JSON.stringify(value) : value;
                        tr.appendChild(td);
                    });
                }
                tbody.appendChild(tr);
            });
        }

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
            if (validation.warnings.length > 0) {
                validation.warnings.forEach(w => {
                    this.addTerminalLine(`[WARNING] ${w}`, 'error');
                });
            }
        } else {
            this.addTerminalLine('[CODE] Validation FAILED:', 'error');
            validation.errors.forEach(e => {
                this.addTerminalLine(`  - ${e}`, 'error');
            });
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

        // Calculate score
        const level = GameLevels[this.currentLevel];
        let levelScore = level.points;

        // Time bonus (max 100 points for completing within 2 minutes)
        const elapsed = Date.now() - this.startTime;
        const timeBonus = Math.max(0, Math.floor(100 - (elapsed / 1000 / 60) * 25));
        levelScore += timeBonus;

        // Hint penalty
        levelScore -= this.hintsUsed * 50;
        levelScore = Math.max(levelScore, 50); // Minimum 50 points

        this.score += levelScore;
        document.getElementById('score').textContent = this.score;

        // Show completion modal
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

        // Disable hint button after 3 hints
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

        // Calculate rank
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

        // Clear progress
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
        const progress = {
            level: this.currentLevel,
            score: this.score
        };
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
