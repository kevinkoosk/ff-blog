<?php
/**
 * initialize.php
 *
 * Run this script once to set up your SQLite blog database.
 * It creates blog.db with the tables: entries, users, settings, and pages.
 * It also sets up a default admin user with role 'admin'.
 * After successful initialization, the script will try to delete itself.
 */

try {
    $db = new PDO('sqlite:../blog.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create the entries table with a "protected" flag (0 = public, 1 = protected)
    $db->exec("
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT,
            entry_date DATE NOT NULL,
            protected INTEGER DEFAULT 0
        );
    ");

    // Create the users table with a "role" field (admin or reader)
    $db->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'reader'
        );
    ");

    // Create the settings table
    $db->exec("
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    ");

    // Insert default settings
    $db->exec("INSERT OR IGNORE INTO settings (key, value) VALUES ('site_name', 'My Blog');");

    // Create the pages table for static content pages (e.g. About, Portfolio, Contact)
    $db->exec("
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
    ");

    // Precomputed hash for password "admin123"
    $adminPasswordHash = '$2y$10$5moEY54znANxl8Or0EaN9uFQi5l/648/ZqDjxLKIHxINp24YaO95q';
    $db->exec("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES ('admin', '$adminPasswordHash', 'admin');");

    echo "<p>Blog database initialized successfully.</p>";

    // Attempt to delete this file for security reasons
    if (unlink(__FILE__)) {
        echo "<p>The initialization script has been deleted.</p>";
    } else {
        echo "<p>Please delete <code>initialize.php</code> manually for security reasons.</p>";
    }
} catch (Exception $e) {
    echo "Initialization failed: " . htmlspecialchars($e->getMessage());
}
?>
