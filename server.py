import hashlib
import hmac
import socket
import threading
import base64

# WARNING: This is a vulnerable implementation!
# This server uses a simple hash construction that is susceptible to length extension attacks
SECRET_KEY = b"secret_key_123"  # In a real system, this would be kept secure

def generate_mac(message):
    """Generate MAC using vulnerable hash(secret || message) construction"""
    # WARNING: This is vulnerable to length extension attacks!
    # The attacker can extend the message and compute a valid MAC without knowing the secret
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message, mac):
    """Verify MAC using vulnerable construction"""
    # WARNING: This is also vulnerable to length extension attacks!
    # The verification uses the same vulnerable construction
    return hmac.compare_digest(generate_mac(message), mac)

def handle_client(client_socket):
    """Handle client connection"""
    try:
        # Receive message and MAC
        data = client_socket.recv(1024).decode()

        # Check if data is in correct format
        if '|' not in data:
            client_socket.send(b"Invalid data format. Expected: base64_message|mac")
            return

        message_b64, mac = data.split('|', 1)

        # Decode base64 message
        message = base64.b64decode(message_b64)

        # Verify MAC
        if verify(message, mac):
            response = "MAC verified successfully"
        else:
            response = "MAC verification failed"

        # Send response
        client_socket.send(response.encode())

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def main():
    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8000))  # Using port 8000
    server.listen(5)

    print("\n=== Vulnerable Server Simulation ===")
    print("WARNING: This server uses an insecure hash construction!")
    print("It is vulnerable to length extension attacks.")
    print(f"Server running on port 8000")
    print("Waiting for connections...")

    while True:
        try:
            client, addr = server.accept()
            print(f"\nAccepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client,))
            client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            break
        except Exception as e:
            print(f"Error accepting connection: {e}")

    server.close()

if __name__ == "__main__":
    main()
