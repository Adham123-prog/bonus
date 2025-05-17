import hashlib
import hmac
import socket
import threading
import base64

# This is a secure implementation using HMAC
SECRET_KEY = b"secret_key_123"  # In a real system, this would be kept secure

def generate_mac(message):
    """Generate MAC using HMAC-SHA256"""
    # HMAC is secure against length extension attacks because:
    # 1. It uses a nested hash construction
    # 2. The secret key is used in both the inner and outer hash
    # 3. The attacker cannot compute a valid MAC without knowing the secret key
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

def verify(message, mac):
    """Verify MAC using constant-time comparison"""
    return hmac.compare_digest(generate_mac(message), mac)

def handle_client(client_socket):
    """Handle client connection"""
    try:
        # Receive message and MAC
        data = client_socket.recv(1024).decode()
        message_b64, mac = data.split('|')
        
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
    server.bind(('localhost', 8001))  # Using port 8001
    server.listen(5)
    
    print("\n=== Secure Server Simulation ===")
    print("This server uses HMAC-SHA256 which is secure against length extension attacks.")
    print("The nested hash construction prevents attackers from extending messages.")
    print(f"Server running on port 8001")
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