<?php
session_start();

// CSRF token lifetime in seconds (e.g. 30 minutes)
define('CSRF_TOKEN_LIFETIME', 1800);

// Generate (or refresh) CSRF token if it isn t set or has expired.
if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time']) || (time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_LIFETIME)) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['csrf_token_time'] = time();
}

try {
    $db = new PDO('sqlite:../blog.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die("Database error: " . htmlspecialchars($e->getMessage()));
}

// --- LOGIN / AUTHENTICATION ---
// Only allow admin login on editor.php
if (!isset($_SESSION['user'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        // CSRF token check
        if (!isset($_POST['csrf_token']) ||
            $_POST['csrf_token'] !== $_SESSION['csrf_token'] ||
            (time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_LIFETIME)
        ) {
            die("CSRF token validation failed or expired.");
        }
        
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$_POST['username']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($_POST['password'], $user['password_hash'])) {
            if ($user['role'] !== 'admin') {
                die("Access denied. Only admin users can access the editor.");
            }
            $_SESSION['user'] = $user;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = "Invalid login credentials.";
        }
    }
    // Display admin login form:
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Admin Login - Blog Editor</title>
        <link href="./css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h1>Admin Login</h1>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" name="username" id="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" name="password" id="password" class="form-control" required>
                </div>
                <button type="submit" name="login" class="btn btn-primary">Login as Admin</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// --- PROCESS FORM SUBMISSIONS ---
// Verify CSRF token for every POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) ||
        $_POST['csrf_token'] !== $_SESSION['csrf_token'] ||
        (time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_LIFETIME)
    ) {
        die("CSRF token validation failed or expired.");
    }
    
    // ENTRY MANAGEMENT (save / update / delete)
    if (isset($_POST['save_entry'])) {
        $title      = trim($_POST['title'] ?? '');
        $content    = trim($_POST['content'] ?? '');
        $category   = trim($_POST['category'] ?? '');
        $entry_date = $_POST['entry_date'] ?? date('Y-m-d');
        $protected  = isset($_POST['protected']) ? 1 : 0;
        
        if ($title && $content) {
            if (!empty($_POST['id'])) {
                // Update existing entry
                $stmt = $db->prepare("UPDATE entries SET title = ?, content = ?, category = ?, entry_date = ?, protected = ? WHERE id = ?");
                $stmt->execute([$title, $content, $category, $entry_date, $protected, $_POST['id']]);
            } else {
                // Insert new entry
                $stmt = $db->prepare("INSERT INTO entries (title, content, category, entry_date, protected) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$title, $content, $category, $entry_date, $protected]);
            }
        }
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    if (isset($_POST['delete_entry']) && !empty($_POST['id'])) {
        $stmt = $db->prepare("DELETE FROM entries WHERE id = ?");
        $stmt->execute([$_POST['id']]);
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    // PAGE MANAGEMENT (save / update / delete)
    if (isset($_POST['save_page'])) {
        $page_title   = trim($_POST['page_title'] ?? '');
        $page_content = trim($_POST['page_content'] ?? '');
        if ($page_title && $page_content) {
            if (!empty($_POST['page_id'])) {
                // Update existing page
                $stmt = $db->prepare("UPDATE pages SET title = ?, content = ? WHERE id = ?");
                $stmt->execute([$page_title, $page_content, $_POST['page_id']]);
            } else {
                // Insert new page
                $stmt = $db->prepare("INSERT INTO pages (title, content) VALUES (?, ?)");
                $stmt->execute([$page_title, $page_content]);
            }
        }
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    if (isset($_POST['delete_page']) && !empty($_POST['page_id'])) {
        $stmt = $db->prepare("DELETE FROM pages WHERE id = ?");
        $stmt->execute([$_POST['page_id']]);
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    // USER MANAGEMENT
    if (isset($_POST['add_user'])) {
        $new_username = trim($_POST['new_username'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $new_role = in_array($_POST['new_role'], ['admin', 'reader']) ? $_POST['new_role'] : 'reader';
        if ($new_username && $new_password) {
            $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
            try {
                $stmt = $db->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
                $stmt->execute([$new_username, $password_hash, $new_role]);
            } catch (Exception $e) {
                $user_error = "Error adding user: " . $e->getMessage();
            }
        }
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    if (isset($_POST['change_password'])) {
        $username = trim($_POST['username'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        if ($username && $new_password) {
            $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
            try {
                $stmt = $db->prepare("UPDATE users SET password_hash = ? WHERE username = ?");
                $stmt->execute([$password_hash, $username]);
            } catch (Exception $e) {
                $user_error = "Error changing password: " . $e->getMessage();
            }
        }
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    // SETTINGS MANAGEMENT
    if (isset($_POST['save_settings'])) {
        $site_name = trim($_POST['site_name'] ?? 'My Blog');
        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('site_name', ?)");
        $stmt->execute([$site_name]);
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

// --- DISPLAY THE EDITOR INTERFACE ---
$site_name = $db->query("SELECT value FROM settings WHERE key = 'site_name'")->fetchColumn();

// If a GET parameter "edit" is provided, fetch that entry's data for pre-filling.
if (isset($_GET['edit'])) {
    $edit_id = (int) $_GET['edit'];
    $stmt = $db->prepare("SELECT * FROM entries WHERE id = ?");
    $stmt->execute([$edit_id]);
    $edit_entry = $stmt->fetch(PDO::FETCH_ASSOC);
}

// If a GET parameter "edit_page" is provided, fetch that page's data for pre-filling.
if (isset($_GET['edit_page'])) {
    $edit_page_id = (int) $_GET['edit_page'];
    $stmt = $db->prepare("SELECT * FROM pages WHERE id = ?");
    $stmt->execute([$edit_page_id]);
    $edit_page = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Admin Editor - <?= htmlspecialchars($site_name) ?></title>
    <link href="./css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <h1>Admin Editor</h1>
    <p>Logged in as: <?= htmlspecialchars($_SESSION['user']['username']) ?> (<?= htmlspecialchars($_SESSION['user']['role']) ?>)
       | <a href="/">Back to front</a> | <a href="users.php">Manage Users</a> | <a href="logout.php">Logout</a></p>
       
    <!-- Entry Management Form -->
    <h2>Entry Management</h2>
    <form method="post" class="mb-4">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <!-- When editing an entry, the hidden ID is pre-filled -->
        <input type="hidden" name="id" value="<?= isset($edit_entry['id']) ? htmlspecialchars($edit_entry['id']) : '' ?>">
        <div class="mb-3">
            <input type="text" name="title" placeholder="Title" class="form-control" required value="<?= isset($edit_entry['title']) ? htmlspecialchars($edit_entry['title']) : '' ?>">
        </div>
        <div class="mb-3">
            <textarea name="content" placeholder="Markdown Content" class="form-control" rows="5" required><?= isset($edit_entry['content']) ? htmlspecialchars($edit_entry['content']) : '' ?></textarea>
        </div>
        <div class="row mb-3">
            <div class="col">
                <input type="text" name="category" placeholder="Category" class="form-control" value="<?= isset($edit_entry['category']) ? htmlspecialchars($edit_entry['category']) : '' ?>">
            </div>
            <div class="col">
                <input type="date" name="entry_date" class="form-control" value="<?= isset($edit_entry['entry_date']) ? htmlspecialchars($edit_entry['entry_date']) : date('Y-m-d') ?>">
            </div>
            <div class="col">
                <div class="form-check mt-2">
                    <input class="form-check-input" type="checkbox" name="protected" id="protected" <?= (isset($edit_entry['protected']) && $edit_entry['protected']) ? 'checked' : '' ?>>
                    <label class="form-check-label" for="protected">Protected</label>
                </div>
            </div>
        </div>
        <div class="d-flex gap-2">
            <button type="submit" name="save_entry" class="btn btn-success">Save Entry</button>
            <button type="submit" name="delete_entry" class="btn btn-danger" onclick="return confirm('Delete this entry?');">Delete Entry</button>
        </div>
    </form>
    
    <!-- Page Management Section -->
    <h2>Page Management</h2>
    <form method="post" class="mb-4">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <!-- When editing a page, the hidden page_id is pre-filled -->
        <input type="hidden" name="page_id" value="<?= isset($edit_page['id']) ? htmlspecialchars($edit_page['id']) : '' ?>">
        <div class="mb-3">
            <input type="text" name="page_title" placeholder="Page Title" class="form-control" required value="<?= isset($edit_page['title']) ? htmlspecialchars($edit_page['title']) : '' ?>">
        </div>
        <div class="mb-3">
            <textarea name="page_content" placeholder="Markdown Content" class="form-control" rows="5" required><?= isset($edit_page['content']) ? htmlspecialchars($edit_page['content']) : '' ?></textarea>
        </div>
        <div class="d-flex gap-2">
            <button type="submit" name="save_page" class="btn btn-success">Save Page</button>
            <button type="submit" name="delete_page" class="btn btn-danger" onclick="return confirm('Delete this page?');">Delete Page</button>
        </div>
    </form>
    
    <!-- Existing Pages Listing -->
    <h3>Existing Pages</h3>
    <table class="table table-striped mb-5">
        <thead>
            <tr>
                <th>Title</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
        <?php
        $pagesStmt = $db->query("SELECT * FROM pages ORDER BY id DESC");
        while ($page = $pagesStmt->fetch(PDO::FETCH_ASSOC)):
        ?>
            <tr>
                <td><?= htmlspecialchars($page['title']) ?></td>
                <td>
                    <a href="<?= $_SERVER['PHP_SELF'] . '?edit_page=' . $page['id'] ?>" class="btn btn-sm btn-primary">Edit</a>
                    <form method="post" style="display:inline;" onsubmit="return confirm('Delete this page?');">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="page_id" value="<?= htmlspecialchars($page['id']) ?>">
                        <button type="submit" name="delete_page" class="btn btn-sm btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
        <?php endwhile; ?>
        </tbody>
    </table>
    
    <!-- Past Entries Listing with Pagination -->
    <h2>Past Entries</h2>
    <!-- Search form for past entries -->
    <form method="get" class="row g-3 mb-4">
        <div class="col-md-6">
            <input type="text" name="entry_search" placeholder="Search entries..." class="form-control" value="<?= htmlspecialchars($_GET['entry_search'] ?? '') ?>">
        </div>
        <div class="col-md-2">
            <button type="submit" class="btn btn-primary w-100">Search</button>
        </div>
    </form>
    <?php
    // Determine current page and limit (25 entries per page)
    $entry_page = max(1, (int)($_GET['entry_page'] ?? 1));
    $limit = 25;
    $offset = ($entry_page - 1) * $limit;

    // Build query for past entries based on optional search
    $entry_search = $_GET['entry_search'] ?? '';
    if ($entry_search !== '') {
        $stmtCount = $db->prepare("SELECT COUNT(*) FROM entries WHERE title LIKE ? OR content LIKE ?");
        $stmtCount->execute(["%$entry_search%", "%$entry_search%"]);
        $totalEntries = $stmtCount->fetchColumn();
        $totalPages = ceil($totalEntries / $limit);
        
        $stmt = $db->prepare("SELECT * FROM entries WHERE title LIKE ? OR content LIKE ? ORDER BY entry_date DESC LIMIT ? OFFSET ?");
        $stmt->execute(["%$entry_search%", "%$entry_search%", $limit, $offset]);
    } else {
        $stmtCount = $db->query("SELECT COUNT(*) FROM entries");
        $totalEntries = $stmtCount->fetchColumn();
        $totalPages = ceil($totalEntries / $limit);
        
        $stmt = $db->query("SELECT * FROM entries ORDER BY entry_date DESC LIMIT $limit OFFSET $offset");
    }
    ?>
    <table class="table table-striped">
        <thead>
            <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Date</th>
                <th>Protected</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
        <?php while ($entry = $stmt->fetch(PDO::FETCH_ASSOC)): ?>
            <tr>
                <td><?= htmlspecialchars($entry['title']) ?></td>
                <td><?= htmlspecialchars($entry['category']) ?></td>
                <td><?= htmlspecialchars($entry['entry_date']) ?></td>
                <td><?= $entry['protected'] ? 'Yes' : 'No' ?></td>
                <td>
                    <a href="<?= $_SERVER['PHP_SELF'] . '?edit=' . $entry['id'] ?>" class="btn btn-sm btn-primary">Edit</a>
                    <form method="post" style="display:inline;" onsubmit="return confirm('Delete this entry?');">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="id" value="<?= htmlspecialchars($entry['id']) ?>">
                        <button type="submit" name="delete_entry" class="btn btn-sm btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
        <?php endwhile; ?>
        </tbody>
    </table>
    <!-- Pagination Links for Past Entries -->
    <?php if ($totalPages > 1): ?>
        <nav aria-label="Past entries pagination">
            <ul class="pagination justify-content-center">
                <?php if ($entry_page > 1): ?>
                    <li class="page-item">
                        <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['entry_page' => $entry_page - 1])) ?>">Previous</a>
                    </li>
                <?php endif; ?>
                <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                    <li class="page-item <?= ($i == $entry_page) ? 'active' : '' ?>">
                        <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['entry_page' => $i])) ?>"><?= $i ?></a>
                    </li>
                <?php endfor; ?>
                <?php if ($entry_page < $totalPages): ?>
                    <li class="page-item">
                        <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['entry_page' => $entry_page + 1])) ?>">Next</a>
                    </li>
                <?php endif; ?>
            </ul>
        </nav>
    <?php endif; ?>
    
    <!-- Accordion for Site Settings -->
    <div class="accordion" id="editorAccordion">

        <div class="accordion-item">
            <h2 class="accordion-header" id="headingSettings">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseSettings" aria-expanded="false" aria-controls="collapseSettings">
                    Site Name
                </button>
            </h2>
            <div id="collapseSettings" class="accordion-collapse collapse" aria-labelledby="headingSettings" data-bs-parent="#editorAccordion">
                <div class="accordion-body">
                    <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="mb-3">
                            <input type="text" name="site_name" value="<?= htmlspecialchars($site_name) ?>" class="form-control" required>
                        </div>
                        <button type="submit" name="save_settings" class="btn btn-secondary">Save Settings</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
    
<script src="./js/bootstrap.bundle.min.js"></script>
</body>
</html>
