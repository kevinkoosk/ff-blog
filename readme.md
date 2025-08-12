# FLAT FILE BLOG (FF BLOG)

Last edited: 2025-08-13

This is a simple flatfile PHP blog which uses sqlite as its storage system.

Authored through vibe coding by Kevin Koo Seng Kiat with assistance from ChatGPT

## Features

1. Publish posts with tagging (categories); date can be set.
2. Publish pages
3. Search posts
4. Protected posts (must be logged in to read)
5. Edit posts
6. Delete posts
7. Change site name
8. User management
9. RSS feed at \[domain]/rss.php



## User management

1. Types of users: Admin and reader
2. Add new users
3. Change user password
4. Delete users (except admin)
5. Search users



## Files

You should see these files:
- index.php 
- display.php 
- editor.php 
- initialize.php
- users.php 
- logout.php 
- Parsedown.php 
- rss.php 
- css/ bootstrap.min.css 
- js/ bootstrap.bundle.min.js


## Installation

1. Unzip the files into the root of the website domain or sub-domain.
2. Ensure that there are no old databases.
3. Run the "initialize.php" script to set up the blog.db database.
4. This will also set up the username "admin" and password "admin123" for the database.



## SQLite database (Important!)

1. Please do not install in subdirectory, always make sure it is in the root directory.
2. SQLite database will be created one level above (../).



## Editing the site

1. For the first time, use username "admin" and password "admin123" to login. (Click "Navigation" to find login form.)
2. Go to editor page to add, edit, and delete blog entries and site pages.
3. Be sure to change the password for the admin.
4. When you are done with this, log out.



## Users

1. While you are in the Editor page, you can select "User Management".
2. You can add new users, delete users, view all users, export users, and change their passwords.
3. From the list of users, you can also change the user from "reader" to "admin" (except for admin, which must remain admin.).

## Media Manager

1. Use my other script ["FF-Media-Manager"](https://github.com/kevinkoosk/ff-media-manager) (also on Github) as the media editor.
2. You can upload images, audio, video, PDF, etc. with that script.
3. It's a separate script, so that you can set up a CDN server on a different domain or a subdomain of your blog. (e.g. https://cdn.domain.net.)

## Copyright

Copyright is claimed by Kevin Koo Seng Kiat.


