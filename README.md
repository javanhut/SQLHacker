# SQL_HACK3R

An interactive educational game that teaches database query skills through a cybersecurity-themed narrative. Progress through 15 missions requiring SQL, PostgreSQL, and NoSQL (MongoDB) queries while infiltrating a fictional corporation's databases.

## Features

- **15 Progressive Missions** - From basic SELECT statements to complex NoSQL operations
- **Three Database Paradigms** - SQL, PostgreSQL (JSONB, arrays, window functions), and MongoDB-style NoSQL
- **Dual Submission System** - Write queries AND implement them in Python or Go
- **Immersive Cyberpunk Theme** - Terminal-style UI with glitch effects
- **Built-in Documentation** - Schema viewer and syntax reference for each database type
- **Scoring System** - Points for accuracy, speed, and minimal hint usage

## Quick Start

### Prerequisites

- [Bun](https://bun.sh) installed on your system

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd SQLGame

# Install Bun (if not already installed)
curl -fsSL https://bun.sh/install | bash
```

### Running the Game

```bash
# Start a local development server
bun --serve .

# Or use bunx to serve static files
bunx serve .
```

Then open your browser to `http://localhost:3000` (or the port shown in terminal).

### Alternative: Direct File Access

Since this is a standalone client-side application with no backend dependencies, you can also open `index.html` directly in your browser:

```bash
open index.html  # macOS
xdg-open index.html  # Linux
start index.html  # Windows
```

## How to Play

1. Click **"INITIALIZE TRAINING"** or press `Enter` to start
2. Read the mission briefing to understand your objective
3. Check the **Schema** tab to view table structures
4. Write your SQL/NoSQL query in the terminal
5. Click **"EXECUTE"** or press `Ctrl+Enter` to test your query
6. Implement the query in Python or Go in the right panel
7. Click **"VALIDATE CODE"** to verify your implementation
8. Click **"SUBMIT MISSION"** to complete the level

## Mission Structure

| Levels | Topic | Database | Difficulty |
|--------|-------|----------|------------|
| 1-4 | SQL Basics | SQL | Beginner |
| 5-7 | Advanced SQL | SQL | Intermediate |
| 8-11 | PostgreSQL Features | PostgreSQL | Intermediate |
| 12-15 | NoSQL Operations | MongoDB | Advanced |

**Total Possible Score: 4,000 points**

## Project Structure

```
SQLGame/
├── index.html          # Main entry point
├── css/
│   └── style.css       # Cyberpunk styling
└── js/
    ├── app.js          # Main application bundle
    ├── game.js         # Game controller logic
    ├── levels.js       # Level definitions and objectives
    ├── queryEngine.js  # SQL/NoSQL parser and executor
    ├── codeValidator.js # Python/Go code validation
    └── database.js     # In-memory database with sample data
```

## Tech Stack

- **Frontend**: Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Database Engine**: Custom in-memory JavaScript implementation
- **Code Validation**: Regex-based syntax checking for Python and Go
- **Storage**: Browser localStorage for progress persistence

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Start game from intro screen |
| `Ctrl+Enter` | Execute query |

## Database Coverage

### SQL
- SELECT, WHERE, JOIN
- ORDER BY, GROUP BY
- Aggregate functions (COUNT, SUM, AVG, MAX, MIN)
- LIKE pattern matching

### PostgreSQL
- JSONB field access (`->`, `->>`)
- Array operations (`@>`, `ANY()`)
- Window functions
- Temporal queries

### NoSQL (MongoDB)
- `db.collection.find()`
- `db.collection.findOne()`
- Multiple field conditions
- Document querying

## Development

To modify or extend the game:

```bash
# Start dev server with live reload
bun --serve . --watch

# Or use a simple HTTP server
bun run --bun bunx serve -s .
```

No build step required - changes to HTML, CSS, or JS files are immediately available.

## License

MIT
