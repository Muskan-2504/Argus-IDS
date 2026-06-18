<?php
include 'db_config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $ip = $_POST['ip'];
    $logs = $_POST['logs'];

    if (!empty($ip) && !empty($logs)) {
        // Store the logs in the database
        $sql = "INSERT INTO intrusion_logs (ip, logs) VALUES ('$ip', '$logs')";
        if ($conn->query($sql) === TRUE) {
            // Perform attack detection
            $attackTypes = [];

            // Example attack detection logic
            $timestamps = explode("\n", $logs);
            if (count($timestamps) > 5) {
                $attackTypes[] = 'Denial of Service (DoS) Attack';
            }
            if (count(array_unique($timestamps)) < count($timestamps)) {
                $attackTypes[] = 'Brute Force Attack';
            }

            if (empty($attackTypes)) {
                $attackTypes[] = 'No significant threat detected';
            }

            // Save detected attacks to the database
            $detectedAttacks = implode(', ', $attackTypes);
            $sql = "UPDATE intrusion_logs SET detected_attacks='$detectedAttacks' WHERE ip='$ip'";
            $conn->query($sql);

            echo json_encode(['status' => 'success', 'attackTypes' => $attackTypes]);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Error: ' . $conn->error]);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Please provide both IP and logs']);
    }
}
?>
