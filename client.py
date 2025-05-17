import hashlib
import binascii
import struct
import sys
import socket
import time
import base64

def check_server_running(port):
    """Check if a server is running on the specified port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except:
        return False

def md5_padding(message_length):
    """Generate MD5 padding for a message of given length"""
    padding = b'\x80'
    padding += b'\x00' * ((56 - (message_length + 1) % 64) % 64)
    padding += struct.pack('<Q', message_length * 8)
    return padding

def perform_vulnerable_attack(original_mac, original_message, append_data):
    """Perform length extension attack against vulnerable server"""
    # Calculate padding for original message
    original_length = len(original_message)
    padding = md5_padding(original_length)
    
    # Create new message with padding
    new_message = original_message + padding + append_data
    
    # For the vulnerable server, we need to compute the new MAC
    # by continuing the hash computation from the original state
    from server import generate_mac
    forged_mac = generate_mac(new_message)
    
    return new_message, forged_mac

def perform_secure_attack(original_mac, original_message, append_data):
    """Attempt length extension attack against secure server"""
    # For the secure server, we'll try to append data
    # but it should fail because HMAC prevents length extension attacks
    new_message = original_message + append_data
    return new_message, original_mac

def format_binary_message(message):
    """Format a binary message for display, showing printable characters and hex for non-printable"""
    result = []
    for byte in message:
        if 32 <= byte <= 126:  # Printable ASCII
            result.append(chr(byte))
        else:
            result.append(f'\\x{byte:02x}')
    return ''.join(result)

def send_to_server(port, message, mac):
    """Send message and MAC to server and get response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', port))
        
        # Convert binary message to base64 for safe transmission
        message_b64 = base64.b64encode(message).decode()
        
        # Send message and MAC in the format expected by server
        data = f"{message_b64}|{mac}"
        sock.send(data.encode())
        
        # Get response
        response = sock.recv(1024).decode()
        sock.close()
        return response
    except Exception as e:
        print(f"Error communicating with server: {e}")
        return None

def attack_vulnerable_server():
    """Perform attack against the vulnerable server"""
    print("\n=== Length Extension Attack Against Vulnerable Server ===\n")
    
    # Check if vulnerable server is running
    if not check_server_running(8000):
        print("Error: Vulnerable server (server.py) is not running!")
        print("Please run 'python server.py' first.")
        return
    
    # Import the vulnerable server
    import server
    
    # Intercepted message
    intercepted_message = b"amount=100&to=alice"
    intercepted_mac = server.generate_mac(intercepted_message)
    
    # Perform attack
    forged_message, forged_mac = perform_vulnerable_attack(
        intercepted_mac,
        intercepted_message,
        b"&admin=true"
    )
    
    print(f"Original message: {intercepted_message.decode()}")
    print(f"Original MAC: {intercepted_mac}")
    print(f"\nForged message: {format_binary_message(forged_message)}")
    print(f"Forged MAC: {forged_mac}")
    
    # Send to server and get response
    response = send_to_server(8000, forged_message, forged_mac)
    if response:
        print(f"\nServer response: {response}")
        if "successfully" in response:
            print("Attack successful! Forged message verified.")
            print("This demonstrates the vulnerability of hash(secret || message) construction.")
        else:
            print("Attack failed. Forged message rejected.")

def attack_secure_server():
    """Perform attack against the secure server"""
    print("\n=== Length Extension Attack Against Secure Server ===\n")
    
    # Check if secure server is running
    if not check_server_running(8001):
        print("Error: Secure server (secure_server.py) is not running!")
        print("Please run 'python secure_server.py' first.")
        return
    
    # Import the secure server
    import secure_server
    
    # Intercepted message
    intercepted_message = b"amount=100&to=alice"
    intercepted_mac = secure_server.generate_mac(intercepted_message)
    
    # Attempt attack
    forged_message, forged_mac = perform_secure_attack(
        intercepted_mac,
        intercepted_message,
        b"&admin=true"
    )
    
    print(f"Original message: {intercepted_message.decode()}")
    print(f"Original MAC: {intercepted_mac}")
    print(f"\nForged message: {format_binary_message(forged_message)}")
    print(f"Forged MAC: {forged_mac}")
    
    # Send to server and get response
    response = send_to_server(8001, forged_message, forged_mac)
    if response:
        print(f"\nServer response: {response}")
        if "successfully" in response:
            print("Attack successful (unexpected)!")
        else:
            print("Attack failed (as expected).")
            print("This demonstrates that HMAC prevents length extension attacks.")

def main():
    print("=== MAC Forgery Attack Demonstration ===")
    print("\nWhich server would you like to attack?")
    print("1. Vulnerable Server (server.py)")
    print("2. Secure Server (secure_server.py)")
    
    while True:
        try:
            choice = input("\nEnter your choice (1 or 2): ").strip()
            if choice == "1":
                attack_vulnerable_server()
                break
            elif choice == "2":
                attack_secure_server()
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")
        except ImportError as e:
            if "server" in str(e):
                print("Error: server.py not found. Please make sure it exists in the current directory.")
            elif "secure_server" in str(e):
                print("Error: secure_server.py not found. Please make sure it exists in the current directory.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

if __name__ == "__main__":
    main() 