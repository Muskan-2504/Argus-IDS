<?php
$host = 'localhost';  // XAMPP default host
$db_name = 'ids';     // Database name
$username = 'root';   // Default XAMPP username
$password = '';       // Default XAMPP password

// Create a connection
$conn = new mysqli($host, $username, $password, $db_name);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
