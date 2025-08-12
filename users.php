<?php
session_start();

// CSRF token lifetime: 30 minutes
define('CSRF_TOKEN_LIFETIME', 1800);
if (!isset($_SESSION['csrf_token']) ||
    !isset($_SESSION['csrf_token_time']) ||
    (time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_LIFETIME)
) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['csrf_token_time'] = time();
}

// Only allow admin users; others are redirected.
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
    header("Location: index.php");
    exit;
}

try {
    $db = new PDO('sqlite:../blog.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die("Database error: " . htmlspecialchars($e->getMessage()));
}
$site_name = $db->query("SELECT value FROM settings WHERE key = 'site_name'")->fetchColumn();

// --- Process POST Requests ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) ||
        $_POST['csrf_token'] !== $_SESSION['csrf_token'] ||
        (time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_LIFETIME)
    ) {
        die("CSRF token validation failed or expired.");
    }
    
    // Update a user's username, password, and role.
    if (isset($_POST['save_user'])) {
        $user_id = $_POST['user_id'] ?? '';
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? '';  // Role from dropdown

        if ($user_id && $username && $role) {
            // Check if this is the default "admin" account.
            $stmt = $db->prepare("SELECT username FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $current_username = $stmt->fetchColumn();
            if ($current_username === 'admin') {
                // Force the role to "admin" for the default admin account.
                $role = 'admin';
            }
            
            if ($password !== '') {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $db->prepare("UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?");
                $stmt->execute([$username, $password_hash, $role, $user_id]);
            } else {
                $stmt = $db->prepare("UPDATE users SET username = ?, role = ? WHERE id = ?");
                $stmt->execute([$username, $role, $user_id]);
            }
        }
        header("Location: " . $_SERVER['PHP_SELF'] . "?" . http_build_query($_GET));
        exit;
    }
    
    // Delete a user (do not allow deletion of the currently logged-in admin).
    if (isset($_POST['delete_user'])) {
        $user_id = $_POST['user_id'] ?? '';
        if ($user_id && $user_id != $_SESSION['user']['id']) {
            $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
        }
        header("Location: " . $_SERVER['PHP_SELF'] . "?" . http_build_query($_GET));
        exit;
    }
    
    // Export all users as CSV (username, password hash, role).
    if (isset($_POST['export_users'])) {
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="users_export.csv"');
        $stmt = $db->query("SELECT username, password_hash, role FROM users");
        $output = fopen('php://output', 'w');
        fputcsv($output, ['Username', 'Password Hash', 'Role']);
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            fputcsv($output, $row);
        }
        fclose($output);
        exit;
    }
}

// --- Pagination and Search for Users ---
$search = trim($_GET['search'] ?? '');
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = 25;
$offset = ($page - 1) * $limit;
$params = [];
$whereSQL = "1=1";
if ($search !== '') {
    $whereSQL .= " AND username LIKE ?";
    $params[] = "%$search%";
}
$countStmt = $db->prepare("SELECT COUNT(*) FROM users WHERE $whereSQL");
$countStmt->execute($params);
$totalUsers = $countStmt->fetchColumn();
$totalPages = ceil($totalUsers / $limit);

$stmt = $db->prepare("SELECT * FROM users WHERE $whereSQL ORDER BY id DESC LIMIT $limit OFFSET $offset");
$stmt->execute($params);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Users Management - <?= htmlspecialchars($site_name) ?></title>
    <link href="./css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <!-- Navigation Links -->
    <nav class="mb-4">
      <a href="index.php" class="btn btn-secondary">Homepage</a>
      <a href="editor.php" class="btn btn-secondary">Editor</a>
      <a href="logout.php" class="btn btn-secondary">Logout</a>
    </nav>
    
    <h1>Users Management</h1>
    
    <!-- Search Form -->
    <form method="get" class="mb-4">
        <div class="row g-3">
            <div class="col-md-6">
                <input type="text" name="search" placeholder="Search users..." class="form-control" value="<?= htmlspecialchars($search) ?>">
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary w-100">Search</button>
            </div>
        </div>
    </form>
    
    <!-- Users Table -->
    <table class="table table-striped">
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>New Password</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php while($user = $stmt->fetch(PDO::FETCH_ASSOC)): ?>
            <tr>
                <td><?= htmlspecialchars($user['id']) ?></td>
                <td>
                    <form method="post" class="d-flex">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="user_id" value="<?= htmlspecialchars($user['id']) ?>">
                        <input type="text" name="username" value="<?= htmlspecialchars($user['username']) ?>" class="form-control">
                </td>
                <td>
                    <select name="role" class="form-select">
                        <option value="reader" <?= $user['role'] === 'reader' ? 'selected' : '' ?>>Reader</option>
                        <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                    </select>
                </td>
                <td>
                    <input type="password" name="password" placeholder="Leave blank to keep unchanged" class="form-control">
                </td>
                <td>
                        <button type="submit" name="save_user" class="btn btn-success btn-sm">Save</button>
                        <?php if ($user['id'] != $_SESSION['user']['id']): ?>
                        <button type="submit" name="delete_user" class="btn btn-danger btn-sm" onclick="return confirm('Delete this user?');">Delete</button>
                        <?php endif; ?>
                    </form>
                </td>
            </tr>
            <?php endwhile; ?>
        </tbody>
    </table>
    
    <!-- Pagination Links -->
    <?php if ($totalPages > 1): ?>
    <nav aria-label="User pagination">
        <ul class="pagination justify-content-center">
            <?php if ($page > 1): ?>
            <li class="page-item">
                <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['page' => $page - 1])) ?>">Previous</a>
            </li>
            <?php endif; ?>
            <?php for ($i = 1; $i <= $totalPages; $i++): ?>
            <li class="page-item <?= ($i == $page) ? 'active' : '' ?>">
                <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['page' => $i])) ?>"><?= $i ?></a>
            </li>
            <?php endfor; ?>
            <?php if ($page < $totalPages): ?>
            <li class="page-item">
                <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['page' => $page + 1])) ?>">Next</a>
            </li>
            <?php endif; ?>
        </ul>
    </nav>
    <?php endif; ?>
    
    <!-- Export Users Button -->
    <form method="post" class="mt-4">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <button type="submit" name="export_users" class="btn btn-primary">Export Users</button>
    </form>
    
    <p></p>
    
    <!-- Accordion for Adding Users and Quick P/W Reset -->
    <div class="accordion" id="editorAccordion">
        <div class="accordion-item">
            <h2 class="accordion-header" id="headingUsers">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseUsers" aria-expanded="false" aria-controls="collapseUsers">
                    Add New Users
                </button>
            </h2>
            <div id="collapseUsers" class="accordion-collapse collapse" aria-labelledby="headingUsers" data-bs-parent="#editorAccordion">
                <div class="accordion-body">
                    <?php if (isset($user_error)): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($user_error) ?></div>
                    <?php endif; ?>
                    <h4>Add New User</h4>
                    <form method="post" class="mb-4">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="mb-3">
                            <input type="text" name="new_username" placeholder="New Username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <input type="password" name="new_password" placeholder="New Password" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <select name="new_role" class="form-select" required>
                                <option value="reader">Reader</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <button type="submit" name="add_user" class="btn btn-primary">Add User</button>
                    </form>
                </div>
            </div>
        </div>
        <div class="accordion-item">
            <h2 class="accordion-header" id="quickpwSettings">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseSettings" aria-expanded="false" aria-controls="collapseSettings">
                    Quick P/W Reset
                </button>
            </h2>
            <div id="collapseSettings" class="accordion-collapse collapse" aria-labelledby="quickpwSettings" data-bs-parent="#editorAccordion">
                <div class="accordion-body">
                    <h4>Change User Password</h4>
                    <form method="post" class="mb-4">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <div class="mb-3">
                            <input type="text" name="username" placeholder="Username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <input type="password" name="new_password" placeholder="New Password" class="form-control" required>
                        </div>
                        <button type="submit" name="change_password" class="btn btn-warning">Change Password</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="./js/bootstrap.bundle.min.js"></script>
</body>
</html>
