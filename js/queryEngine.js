// SQL_HACK3R - Query Engine
// Parses and executes SQL, PostgreSQL, and NoSQL queries against the fake database

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

    // SQL/PostgreSQL Query Parser and Executor
    executeSQL(query) {
        const upperQuery = query.toUpperCase();

        // Determine query type
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
        // Parse the SELECT query
        const parsed = this.parseSelect(query);
        if (parsed.error) {
            return { success: false, error: parsed.error };
        }

        const dbData = this.currentDbType === 'postgresql' ?
            { ...this.db.sql, ...this.db.postgresql } :
            this.db.sql;

        // Get the table data
        const table = dbData[parsed.table];
        if (!table) {
            return { success: false, error: `Table '${parsed.table}' not found.` };
        }

        let results = [...table.data];

        // Handle JOINs
        if (parsed.joins && parsed.joins.length > 0) {
            for (const join of parsed.joins) {
                const joinTable = dbData[join.table];
                if (!joinTable) {
                    return { success: false, error: `Table '${join.table}' not found.` };
                }
                results = this.performJoin(results, joinTable.data, join, parsed.table);
            }
        }

        // Apply WHERE clause
        if (parsed.where) {
            results = this.applyWhere(results, parsed.where);
        }

        // Apply GROUP BY
        if (parsed.groupBy) {
            results = this.applyGroupBy(results, parsed.groupBy, parsed.columns, parsed.aggregates);
        }

        // Apply HAVING
        if (parsed.having) {
            results = this.applyHaving(results, parsed.having);
        }

        // Apply ORDER BY
        if (parsed.orderBy) {
            results = this.applyOrderBy(results, parsed.orderBy);
        }

        // Apply LIMIT
        if (parsed.limit) {
            results = results.slice(0, parsed.limit);
        }

        // Select columns
        if (parsed.columns[0] !== '*' && !parsed.groupBy) {
            results = this.selectColumns(results, parsed.columns, parsed.aliases);
        }

        // Get column names for display
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

        // Remove extra whitespace and normalize
        let q = query.replace(/\s+/g, ' ').trim();

        // Extract LIMIT
        const limitMatch = q.match(/\sLIMIT\s+(\d+)/i);
        if (limitMatch) {
            result.limit = parseInt(limitMatch[1]);
            q = q.replace(/\sLIMIT\s+\d+/i, '');
        }

        // Extract ORDER BY
        const orderMatch = q.match(/\sORDER\s+BY\s+(.+?)(?=\s*$)/i);
        if (orderMatch) {
            result.orderBy = this.parseOrderBy(orderMatch[1]);
            q = q.replace(/\sORDER\s+BY\s+.+?(?=\s*$)/i, '');
        }

        // Extract HAVING
        const havingMatch = q.match(/\sHAVING\s+(.+?)(?=\sORDER|\sLIMIT|\s*$)/i);
        if (havingMatch) {
            result.having = havingMatch[1].trim();
            q = q.replace(/\sHAVING\s+.+?(?=\sORDER|\sLIMIT|\s*$)/i, '');
        }

        // Extract GROUP BY
        const groupMatch = q.match(/\sGROUP\s+BY\s+(.+?)(?=\sHAVING|\sORDER|\sLIMIT|\s*$)/i);
        if (groupMatch) {
            result.groupBy = groupMatch[1].split(',').map(g => g.trim());
            q = q.replace(/\sGROUP\s+BY\s+.+?(?=\sHAVING|\sORDER|\sLIMIT|\s*$)/i, '');
        }

        // Extract WHERE
        const whereMatch = q.match(/\sWHERE\s+(.+?)(?=\sGROUP|\sHAVING|\sORDER|\sLIMIT|\s*$)/i);
        if (whereMatch) {
            result.where = whereMatch[1].trim();
            q = q.replace(/\sWHERE\s+.+?(?=\sGROUP|\sHAVING|\sORDER|\sLIMIT|\s*$)/i, '');
        }

        // Extract JOINs
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

        // Extract FROM table
        const fromMatch = q.match(/\sFROM\s+(\w+)(?:\s+AS\s+(\w+))?/i);
        if (!fromMatch) {
            return { error: 'Invalid query: FROM clause not found.' };
        }
        result.table = fromMatch[1].toLowerCase();
        result.tableAlias = fromMatch[2] ? fromMatch[2].toLowerCase() : null;

        // Extract SELECT columns
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

        // Split by comma, but respect parentheses
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
            // Check for alias
            const aliasMatch = part.match(/(.+?)\s+AS\s+(\w+)/i);
            let colExpr = aliasMatch ? aliasMatch[1].trim() : part.trim();
            const alias = aliasMatch ? aliasMatch[2] : null;

            // Check for aggregate functions
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
                // Handle table.column notation
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

        // Parse join condition (e.g., "users.id = access_logs.user_id")
        const condMatch = condition.match(/(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)/);
        if (!condMatch) {
            return leftData; // Fallback if condition parsing fails
        }

        const leftKey = condMatch[2];
        const rightKey = condMatch[4];

        for (const leftRow of leftData) {
            let matched = false;
            for (const rightRow of rightData) {
                if (leftRow[leftKey] == rightRow[rightKey]) {
                    // Merge rows, prefixing with table name if collision
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
            // For LEFT JOIN, include unmatched left rows
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
        // Handle AND/OR
        const orParts = this.splitLogical(condition, 'OR');
        if (orParts.length > 1) {
            return orParts.some(part => this.evaluateCondition(row, part.trim()));
        }

        const andParts = this.splitLogical(condition, 'AND');
        if (andParts.length > 1) {
            return andParts.every(part => this.evaluateCondition(row, part.trim()));
        }

        // Handle parentheses
        if (condition.startsWith('(') && condition.endsWith(')')) {
            return this.evaluateCondition(row, condition.slice(1, -1));
        }

        // Handle NOT
        if (condition.toUpperCase().startsWith('NOT ')) {
            return !this.evaluateCondition(row, condition.substring(4).trim());
        }

        // Handle IN clause
        const inMatch = condition.match(/(\w+)\s+IN\s*\((.+)\)/i);
        if (inMatch) {
            const column = inMatch[1];
            const values = inMatch[2].split(',').map(v => v.trim().replace(/'/g, ''));
            return values.includes(String(row[column]));
        }

        // Handle NOT IN clause
        const notInMatch = condition.match(/(\w+)\s+NOT\s+IN\s*\((.+)\)/i);
        if (notInMatch) {
            const column = notInMatch[1];
            const values = notInMatch[2].split(',').map(v => v.trim().replace(/'/g, ''));
            return !values.includes(String(row[column]));
        }

        // Handle LIKE clause
        const likeMatch = condition.match(/(\w+)\s+LIKE\s+'(.+)'/i);
        if (likeMatch) {
            const column = likeMatch[1];
            const pattern = likeMatch[2].replace(/%/g, '.*').replace(/_/g, '.');
            const regex = new RegExp(`^${pattern}$`, 'i');
            return regex.test(String(row[column] || ''));
        }

        // Handle IS NULL / IS NOT NULL
        const isNullMatch = condition.match(/(\w+)\s+IS\s+(NOT\s+)?NULL/i);
        if (isNullMatch) {
            const column = isNullMatch[1];
            const isNot = !!isNullMatch[2];
            const value = row[column];
            const isNull = value === null || value === undefined || value === '';
            return isNot ? !isNull : isNull;
        }

        // Handle BETWEEN
        const betweenMatch = condition.match(/(\w+)\s+BETWEEN\s+(.+)\s+AND\s+(.+)/i);
        if (betweenMatch) {
            const column = betweenMatch[1];
            const low = this.parseValue(betweenMatch[2].trim());
            const high = this.parseValue(betweenMatch[3].trim());
            const value = row[column];
            return value >= low && value <= high;
        }

        // Handle comparison operators
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
        let current = '';
        let depth = 0;
        const regex = new RegExp(`\\s+${operator}\\s+`, 'gi');
        const words = condition.split(regex);

        // Simple split - may need improvement for complex nested conditions
        let temp = '';
        for (let i = 0; i < condition.length; i++) {
            const char = condition[i];
            if (char === '(') depth++;
            if (char === ')') depth--;
            temp += char;

            // Check if we're at a logical operator at depth 0
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
        // Remove quotes
        if ((value.startsWith("'") && value.endsWith("'")) ||
            (value.startsWith('"') && value.endsWith('"'))) {
            return value.slice(1, -1);
        }
        // Try parsing as number
        const num = parseFloat(value);
        if (!isNaN(num)) return num;
        // Boolean
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

            // Add group by columns
            for (const col of groupBy) {
                result[col] = rows[0][col];
            }

            // Calculate aggregates
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

    // NoSQL Query Parser and Executor (MongoDB-style)
    executeNoSQL(query) {
        try {
            // Parse the query
            query = query.trim();

            // Handle db.collection.method() syntax
            const match = query.match(/db\.(\w+)\.(\w+)\((.*)\)/s);
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
                // Parse JSON arguments
                try {
                    // Handle multiple arguments
                    const parsed = this.parseNoSQLArgs(argsStr);
                    args = parsed;
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
        // Simple JSON parser for MongoDB-style queries
        // Convert single quotes to double quotes for JSON parsing
        let normalized = argsStr
            .replace(/'/g, '"')
            .replace(/(\w+):/g, '"$1":')
            .replace(/"(\$\w+)":/g, '"$1":');

        // Handle multiple arguments separated by comma at top level
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
        // Handle string literals
        if (str.startsWith('"') || str.startsWith("'")) {
            return str.slice(1, -1);
        }

        // Try to parse as JSON
        try {
            // Normalize the string for JSON parsing
            let normalized = str
                .replace(/'/g, '"')
                .replace(/([{,]\s*)(\w+)\s*:/g, '$1"$2":')
                .replace(/:\s*'([^']+)'/g, ':"$1"');

            return JSON.parse(normalized);
        } catch (e) {
            // If it's a simple value
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

        // Apply projection if specified
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
            // Handle operators
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
                // Handle comparison operators
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
                // Array equality
                if (!Array.isArray(docValue) || JSON.stringify(docValue) !== JSON.stringify(value)) {
                    return false;
                }
            } else {
                // Direct equality
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

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = QueryEngine;
}
