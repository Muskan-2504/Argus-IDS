<?php
include 'db_config.php';

if ($_SERVER["REQUEST_METHOD"] == "GET") {
    $ip = $_GET['ip'];

    if (!empty($ip)) {
        $sql = "SELECT detected_attacks FROM intrusion_logs WHERE ip='$ip'";
        $result = $conn->query($sql);

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            echo json_encode(['status' => 'success', 'detectedAttacks' => $row['detected_attacks']]);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'No records found for the provided IP']);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'IP address not provided']);
    }
}
?>
