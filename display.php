<?php
session_start();

// CSRF token lifetime: 30 minutes
define('CSRF_TOKEN_LIFETIME', 1800);
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

$site_name = $db->query("SELECT value FROM settings WHERE key = 'site_name'")->fetchColumn();

// Include Parsedown to convert Markdown to HTML.
require_once 'Parsedown.php';
$Parsedown = new Parsedown();

// --- Single View for a Blog Post or Static Page ---
if (isset($_GET['view']) && isset($_GET['id'])) {
    $viewType = $_GET['view'];
    $id = (int) $_GET['id'];
    if ($viewType === 'entry') {
        $stmt = $db->prepare("SELECT * FROM entries WHERE id = ?");
        $stmt->execute([$id]);
        $entry = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($entry) {
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title><?= htmlspecialchars($entry['title']) ?> - <?= htmlspecialchars($site_name) ?></title>
                <link href="./css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
                <div class="container mt-5">
                    <!-- Header with site title and back link -->
                    <header class="mb-4">
                        <a href="index.php" class="btn btn-secondary">&larr; Back</a>
                        <h1 class="d-inline ms-3"><?= htmlspecialchars($site_name) ?></h1>
                    </header>
                    
                    <h2><?= htmlspecialchars($entry['title']) ?></h2>
                    
                    <?php if ($entry['protected'] && !isset($_SESSION['user'])): ?>
                        <div class="alert alert-warning">
                            This post is protected and can be viewed only by logged in users.
                        </div>
                    <?php else: ?>
                        <div><?= $Parsedown->text($entry['content']) ?></div>
                        <p>
                            <small>
                                Date: <?= htmlspecialchars($entry['entry_date']) ?>;
                                Category: <?= htmlspecialchars($entry['category']) ?>
                                <?php if ($entry['protected']): ?>
                                    | <span class="badge bg-warning text-dark">Protected</span>
                                <?php endif; ?>
                            </small>
                        </p>
                    <?php endif; ?>
                    
                    <p><a href="index.php" class="btn btn-link">Back to list</a></p>
                </div>
            </body>
            </html>
            <?php
            exit;
        } else {
            echo "Blog entry not found.";
            exit;
        }
    } elseif ($viewType === 'page') {
        $stmt = $db->prepare("SELECT * FROM pages WHERE id = ?");
        $stmt->execute([$id]);
        $pageData = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($pageData) {
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title><?= htmlspecialchars($pageData['title']) ?> - <?= htmlspecialchars($site_name) ?></title>
                <link href="./css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
                <div class="container mt-5">
                    <!-- Header with site title and back link -->
                    <header class="mb-4">
                        <a href="index.php" class="btn btn-secondary">&larr; Back</a>
                        <h1 class="d-inline ms-3"><?= htmlspecialchars($site_name) ?></h1>
                    </header>
                    
                    <h2><?= htmlspecialchars($pageData['title']) ?></h2>
                    <div><?= $Parsedown->text($pageData['content']) ?></div>
                    <p><a href="index.php" class="btn btn-link">Back to list</a></p>
                </div>
            </body>
            </html>
            <?php
            exit;
        } else {
            echo "Page not found.";
            exit;
        }
    }
}

// --- Process Login ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
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
        $_SESSION['user'] = $user;
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Invalid login credentials.";
    }
}

// --- Build Query for Blog Entries Listing (show all posts, including protected) ---
$whereSQL = "1=1";
$params = [];

$search   = trim($_GET['search'] ?? '');
$category = trim($_GET['category'] ?? '');
$page     = max(1, (int) ($_GET['page'] ?? 1));
$limit    = 25;  // 25 entries per page
$offset   = ($page - 1) * $limit;

if ($search !== '') {
    $whereSQL .= " AND (title LIKE ? OR content LIKE ?)";
    $params[] = "%$search%";
    $params[] = "%$search%";
}
if ($category !== '') {
    $whereSQL .= " AND category = ?";
    $params[] = $category;
}

// Get total count for pagination.
$countStmt = $db->prepare("SELECT COUNT(*) FROM entries WHERE $whereSQL");
$countStmt->execute($params);
$totalEntries = $countStmt->fetchColumn();
$totalPages = ceil($totalEntries / $limit);

// Get the entries (with additional fields for display).
$stmt = $db->prepare("SELECT id, title, category, entry_date, protected FROM entries WHERE $whereSQL ORDER BY entry_date DESC LIMIT $limit OFFSET $offset");
$stmt->execute($params);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title><?= htmlspecialchars($site_name) ?></title>
    <link href="./css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <!-- Site Header -->
        <header class="mb-4">
            <h1><?= htmlspecialchars($site_name) ?></h1>
        </header>
        
        
        <!-- Filter Form -->
        <form method="get" class="row g-3 mb-4">
            <div class="col-md-5">
                <input type="text" name="search" placeholder="Search posts..." class="form-control" value="<?= htmlspecialchars($search) ?>">
            </div>
            <div class="col-md-5">
                <input type="text" name="category" placeholder="Category..." class="form-control" value="<?= htmlspecialchars($category) ?>">
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary w-100">Filter</button>
            </div>
        </form>
        

        
        <!-- Blog Entries Listing -->
        <h2>Blog Entries</h2>
        <ul class="list-group mb-4">
            <?php while ($row = $stmt->fetch(PDO::FETCH_ASSOC)): ?>
                <li class="list-group-item">
                    <a href="index.php?view=entry&id=<?= htmlspecialchars($row['id']) ?>">
                        <?= htmlspecialchars($row['title']) ?>
                    </a>
                    <br>
                    <small>
                        Date: <?= htmlspecialchars($row['entry_date']) ?>; 
                        Category: <?= htmlspecialchars($row['category']) ?>
                        <?php if ($row['protected']): ?>
                            <span class="badge bg-warning text-dark">Protected</span>
                        <?php endif; ?>
                    </small>
                </li>
            <?php endwhile; ?>
        </ul>
        
        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
        <nav aria-label="Page navigation">
            <ul class="pagination justify-content-center">
                <?php if ($page > 1): ?>
                    <li class="page-item">
                        <a class="page-link" href="?<?= http_build_query(array_merge($_GET, ['page' => $page - 1])) ?>">Previous</a>
                    </li>
                <?php endif; ?>
    
                <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                    <li class="page-item <?= ($i === $page) ? 'active' : '' ?>">
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


        <!-- Pages Listing in a Collapsible Accordion -->
        <div class="accordion mb-4" id="pagesAccordion">
          <div class="accordion-item">
            <h2 class="accordion-header" id="headingPages">
              <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapsePages" aria-expanded="false" aria-controls="collapsePages">
                Navigation
              </button>
            </h2>
            <div id="collapsePages" class="accordion-collapse collapse">
              <div class="accordion-body">
                          <nav class="mb-4">
                  <?php
                  $pagesStmt = $db->query("SELECT id, title FROM pages ORDER BY id ASC");
                  while ($pageRow = $pagesStmt->fetch(PDO::FETCH_ASSOC)):
                  ?>
                          <a href="index.php?view=page&id=<?= htmlspecialchars($pageRow['id']) ?>" class="btn btn-secondary">
                              <?= htmlspecialchars($pageRow['title']) ?>
                          </a>
                      </li>
                         
                  <?php endwhile; ?>
    </nav>
                
                                <!-- Navigation / Login Area -->
        <div class="mb-4">
            <?php if (isset($_SESSION['user'])): ?>
                <p>
                    Logged in as: <?= htmlspecialchars($_SESSION['user']['username']) ?> (<?= htmlspecialchars($_SESSION['user']['role']) ?>)
                    <?php if ($_SESSION['user']['role'] === 'admin'): ?>
                        | <a href="editor.php">Admin Editor</a>
                    <?php endif; ?>
                    | <a href="logout.php">Logout</a>
                </p>
            <?php else: ?>
                <form method="post" class="row g-3 mb-4">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <div class="col-md-3">
                        <input type="text" name="username" placeholder="Username" class="form-control" required>
                    </div>
                    <div class="col-md-3">
                        <input type="password" name="password" placeholder="Password" class="form-control" required>
                    </div>
                    <div class="col-md-3">
                        <button type="submit" name="login" class="btn btn-primary w-100">Login</button>
                    </div>
                </form>
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
            <?php endif; ?>
        </div>

                
              </div>
            </div>
          </div>
        </div>        
        

        
    </div>
    
    <script src="./js/bootstrap.bundle.min.js"></script>
</body>
</html>
