// SQL_HACK3R - Code Validator
// Validates Python and Go code implementations

class CodeValidator {
    constructor() {
        this.currentLanguage = 'python';
    }

    setLanguage(lang) {
        this.currentLanguage = lang;
    }

    // Get code template for the current level
    getTemplate(level, language) {
        const templates = {
            python: {
                sql: `# Python SQL Implementation
# Use the sqlite3 or psycopg2 library to execute your query

import sqlite3  # or: import psycopg2

def execute_query(connection):
    """
    Execute the SQL query and return the results.

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

    return results`,

                postgresql: `# Python PostgreSQL Implementation
# Use psycopg2 for PostgreSQL-specific features

import psycopg2
from psycopg2.extras import RealDictCursor

def execute_query(connection):
    """
    Execute the PostgreSQL query and return the results.

    Args:
        connection: psycopg2 connection object

    Returns:
        List of dictionaries containing query results
    """
    cursor = connection.cursor(cursor_factory=RealDictCursor)

    # TODO: Write your PostgreSQL query here
    # You can use PostgreSQL-specific features like:
    # - JSONB operators: ->, ->>, @>, etc.
    # - Array operations: ANY(), ALL(), array_agg()
    # - Window functions: ROW_NUMBER(), RANK(), etc.
    query = """
        YOUR QUERY HERE
    """

    cursor.execute(query)
    results = cursor.fetchall()

    return results`,

                nosql: `# Python MongoDB Implementation
# Use pymongo for NoSQL operations

from pymongo import MongoClient

def execute_query(collection):
    """
    Execute the MongoDB query and return the results.

    Args:
        collection: pymongo collection object

    Returns:
        List of documents matching the query
    """
    # TODO: Write your MongoDB query here
    # Example operations:
    # - collection.find({query})
    # - collection.find_one({query})
    # - collection.aggregate([pipeline])

    query = {
        # YOUR QUERY HERE
    }

    results = list(collection.find(query))

    return results`
            },

            go: {
                sql: `// Go SQL Implementation
// Use database/sql with appropriate driver

package main

import (
    "database/sql"
    _ "github.com/lib/pq" // or: _ "github.com/go-sql-driver/mysql"
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

    // Get column names
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
}`,

                postgresql: `// Go PostgreSQL Implementation
// Use database/sql with lib/pq driver

package main

import (
    "database/sql"
    "encoding/json"
    _ "github.com/lib/pq"
)

func executeQuery(db *sql.DB) ([]map[string]interface{}, error) {
    // TODO: Write your PostgreSQL query here
    // PostgreSQL-specific features available:
    // - JSONB: use json.RawMessage for scanning
    // - Arrays: use pq.Array() for scanning
    // - Custom types: implement sql.Scanner interface

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
}`,

                nosql: `// Go MongoDB Implementation
// Use go.mongodb.org/mongo-driver

package main

import (
    "context"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
)

func executeQuery(collection *mongo.Collection) ([]bson.M, error) {
    ctx := context.Background()

    // TODO: Write your MongoDB query here
    // Example operations:
    // - collection.Find(ctx, filter)
    // - collection.FindOne(ctx, filter)
    // - collection.Aggregate(ctx, pipeline)

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
}`
            }
        };

        return templates[language][level.dbType] || templates[language].sql;
    }

    // Validate user's code against expected patterns
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

        // Check for required elements based on level
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

        // Check for forbidden patterns (security issues, etc.)
        for (const forbidden of requirements.forbidden) {
            if (this.checkPattern(code, forbidden.pattern)) {
                validation.errors.push(forbidden.message);
            }
        }

        // Check if the query matches expected solution
        const queryMatch = this.extractAndValidateQuery(code, level, language);
        if (!queryMatch.valid) {
            validation.errors.push(queryMatch.error);
        } else {
            validation.score += 50;
        }

        // Calculate final score
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
                requirements.recommended.push(
                    { pattern: /"""[\s\S]*"""|'''[\s\S]*'''/, message: 'Consider using multi-line strings for complex queries.' }
                );
                requirements.forbidden.push(
                    { pattern: /f["'].*\{.*\}.*["']|%s|\.format\(/, message: 'WARNING: Avoid string interpolation in SQL queries - use parameterized queries to prevent SQL injection!' }
                );
            } else if (level.dbType === 'nosql') {
                requirements.required.push(
                    { pattern: /collection\.(find|find_one|aggregate|count|distinct)/, message: 'Must use a MongoDB collection method (find, aggregate, etc.).' }
                );
                requirements.recommended.push(
                    { pattern: /list\s*\(|\.to_list\(/, message: 'Consider converting cursor to list for results.' }
                );
            }
        } else if (language === 'go') {
            if (level.dbType === 'sql' || level.dbType === 'postgresql') {
                requirements.required.push(
                    { pattern: /db\.Query|db\.QueryRow/, message: 'Must execute query using db.Query() or db.QueryRow().' },
                    { pattern: /rows\.Scan|row\.Scan/, message: 'Must scan results using Scan().' },
                    { pattern: /defer\s+rows\.Close\(\)/, message: 'Must defer closing rows to prevent resource leaks.' }
                );
                requirements.forbidden.push(
                    { pattern: /fmt\.Sprintf.*SELECT|".*"\s*\+\s*.*SELECT/i, message: 'WARNING: Avoid string concatenation in SQL queries - use parameterized queries!' }
                );
            } else if (level.dbType === 'nosql') {
                requirements.required.push(
                    { pattern: /collection\.(Find|FindOne|Aggregate)/, message: 'Must use a MongoDB collection method.' },
                    { pattern: /cursor\.(All|Next|Decode)/, message: 'Must process cursor results.' },
                    { pattern: /defer\s+cursor\.Close/, message: 'Must defer closing cursor.' }
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
        // Extract the query from the code
        let query = '';

        if (language === 'python') {
            // Look for triple-quoted strings or regular strings assigned to query variable
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
            // Look for backtick strings or regular strings
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

        // Check if query contains expected keywords from the level
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

    // Generate hints for code implementation
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

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CodeValidator;
}
