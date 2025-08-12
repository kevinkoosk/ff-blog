<?php
// rss.php

// Set the content type to XML
header("Content-Type: application/rss+xml; charset=UTF-8");

// Connect to the SQLite database
try {
    $db = new PDO('sqlite:../blog.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die("Database connection error: " . htmlspecialchars($e->getMessage()));
}

// Define how many entries to include in the feed (latest 25 is a common choice)
$limit = 25;

// Retrieve the latest entries ordered by entry_date descending
$stmt = $db->prepare("SELECT * FROM entries ORDER BY entry_date DESC LIMIT ?");
$stmt->bindValue(1, $limit, PDO::PARAM_INT);
$stmt->execute();
$entries = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Define the base URL for individual entries.
// Adjust this to your site's domain/path where each entry can be viewed.
$base_url = "http://d4.grundnorm.org/index.php?view=entry&id=";

// Begin outputting the RSS feed
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
?>
<rss version="2.0">
  <channel>
    <title>Grundnorm.org Blog RSS Feed</title>
    <link>http://d4.grundnorm.org/</link>
    <description>This RSS feed contains the latest blog entries.</description>
    <language>en-us</language>
    <?php foreach ($entries as $entry): 
      // Format the publication date for RSS (RFC 822 format)
      $pubDate = date(DATE_RSS, strtotime($entry['entry_date']));
      // Create a hyperlink to the entry (customize as needed)
      $link = $base_url . urlencode($entry['id']);
    ?>
    <item>
      <title><?= htmlspecialchars($entry['title']) ?></title>
      <link><?= htmlspecialchars($link) ?></link>
      <description><![CDATA[Category: <?= htmlspecialchars($entry['category']) ?>]]></description>
      <pubDate><?= $pubDate ?></pubDate>
      <guid isPermaLink="true"><?= htmlspecialchars($link) ?></guid>
    </item>
    <?php endforeach; ?>
  </channel>
</rss>
