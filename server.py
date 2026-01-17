import socket
import threading
import shutil
import os
import time
from colorama import Fore, Style, init

init(autoreset=True)

HOST = '0.0.0.0'
PORT = 5555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

active_agents = {}
public_keys = {}
offline_mailbox = {}

def print_centered(text, color=Fore.WHITE):
    try: width = shutil.get_terminal_size().columns
    except: width = 80
    padding = max(0, (width - len(text)) // 2)
    print(" " * padding + color + text)

def handle_client(client, agent_id):
    while True:
        try:
            data = client.recv(10240)
            if not data: break
            
            command_packet = data.decode('utf-8')
            
            if command_packet.startswith("[GET_KEY]"):
                target_request = command_packet.split("]")[1]
                if target_request in public_keys:
                    response = f"[KEY_FOUND]{public_keys[target_request]}"
                    client.send(response.encode('utf-8'))
                else:
                    client.send(b"[KEY_NOT_FOUND]")

            elif command_packet.startswith("[MSG]"):
                _, content = command_packet.split("]", 1)
                target_id, encrypted_blob = content.split("|", 1)
                
                packet_to_send = f"[INCOMING]{agent_id}|{encrypted_blob}"
                
                if target_id in active_agents:
                    try:
                        active_agents[target_id].send(packet_to_send.encode('utf-8'))
                    except:
                        if target_id not in offline_mailbox: offline_mailbox[target_id] = []
                        offline_mailbox[target_id].append(packet_to_send)
                else:
                    if target_id not in offline_mailbox: offline_mailbox[target_id] = []
                    offline_mailbox[target_id].append(packet_to_send)
                    print_centered(f"[LOG] MSG BUFFERED FOR: {target_id}", Fore.YELLOW)

        except Exception as e:
            break
    
    if agent_id in active_agents: del active_agents[agent_id]
    client.close()
    print_centered(f"[-] AGENT DISCONNECTED: {agent_id}", Fore.RED)

def receive():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_centered("G.I.D SECURE KEY SERVER v6.0 (E2EE ENABLED)", Fore.GREEN)
    print_centered("-" * 50, Fore.WHITE)
    print_centered("[*] WAITING FOR SECURE HANDSHAKES...", Fore.CYAN)
    
    while True:
        client, address = server.accept()
        try:
            initial_data = client.recv(4096).decode('utf-8')
            
            if initial_data.startswith("[REGISTER]"):
                _, payload = initial_data.split("]", 1)
                agent_id, pub_key_pem = payload.split("|", 1)
                
                active_agents[agent_id] = client
                public_keys[agent_id] = pub_key_pem
                
                print_centered(f"[+] REGISTERED KEY FOR AGENT: {agent_id}", Fore.GREEN)
                
                if agent_id in offline_mailbox:
                    for saved_msg in offline_mailbox[agent_id]:
                        client.send(saved_msg.encode('utf-8'))
                        time.sleep(0.2)
                    del offline_mailbox[agent_id]

                thread = threading.Thread(target=handle_client, args=(client, agent_id))
                thread.start()
        except:
            client.close()

if __name__ == "__main__":
    receive()