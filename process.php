<?php
class Database {
    private $host = "localhost";
    private $db_name = "api_project";
    private $username = "root";
    private $password = "root";
    private $conn;

    public function connect() {
        $this->conn = null;
        try {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            echo "Connection failed: " . $e->getMessage();
        }
        return $this->conn;
    }
}

class User {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function register($username, $email, $password) {
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $query = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashedPassword);

        if ($stmt->execute()) {
            return true;
        }
        return false;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Input Validation
    $username = htmlspecialchars($_POST['username']);
    $email = htmlspecialchars($_POST['email']);
    $password = htmlspecialchars($_POST['password']);

    // Database Connection
    $database = new Database();
    $db = $database->connect();

    // User Registration
    $user = new User($db);
    if ($user->register($username, $email, $password)) {
        echo "User registered successfully!";
    } else {
        echo "Failed to register user.";
    }
}
?>
