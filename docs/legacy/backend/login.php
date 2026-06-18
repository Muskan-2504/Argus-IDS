<?php
// login.php

$host = "localhost"; // MySQL server address
$user = "root"; // Default MySQL username
$pass = ""; // Default MySQL password (empty for XAMPP)
$db = "ids"; // Your database name

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process the login request
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'];
    $email = $_POST['email'];

    $query = "INSERT INTO users (name, email) VALUES ('$name', '$email')";
    if ($conn->query($query) === TRUE) {
        echo json_encode(['status' => 'success']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Login failed']);
    }
}

$conn->close();
?>
