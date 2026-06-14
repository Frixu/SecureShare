# client/main.py

import argparse
import sys
from pathlib import Path

from client.client import SecureShareClient
from client.utils.logger import get_client_logger
from shared.constants import DEFAULT_HOST, DEFAULT_PORT, STATE_AUTHENTICATED

logger = get_client_logger()


def print_menu() -> None:
    print("\n" + "="*40)
    print("        MENU SECURESHARE CLIENT")
    print("="*40)
    print("  1. Wyślij plik na serwer (Upload)")
    print("  2. Pobierz plik z serwera (Download)")
    print("  3. Wyloguj i wyjdź (Exit)")
    print("="*40)


def run_interactive_cli(host: str, port: int) -> None:
    print("=== SecureShare CLI Client ===")
    
    # 1. Ask for host/port if not default or confirm
    user_host = input(f"Podaj host serwera [{host}]: ").strip() or host
    user_port_str = input(f"Podaj port serwera [{port}]: ").strip()
    
    user_port = port
    if user_port_str:
        try:
            user_port = int(user_port_str)
        except ValueError:
            print("Port musi być liczbą. Używanie domyślnego portu.")

    client = SecureShareClient(host=user_host, port=user_port)

    # 2. Login Loop
    logged_in = False
    while not logged_in:
        username = input("Login: ").strip()
        if not username:
            print("Nazwa użytkownika nie może być pusta.")
            continue
            
        import getpass
        try:
            # Try to get password securely
            password = getpass.getpass("Hasło: ")
        except Exception:
            # Fallback for environments where getpass is not supported
            password = input("Hasło: ")
            
        if not password:
            print("Hasło nie może być puste.")
            continue

        # Connect
        if not client.connect():
            print("Nie można nawiązać połączenia z serwerem. Czy chcesz spróbować ponownie?")
            choice = input("Spróbować ponownie? (t/n) [t]: ").strip().lower()
            if choice == 'n':
                print("Do widzenia!")
                sys.exit(0)
            continue

        # Login
        if client.login(username, password):
            logged_in = True
        else:
            print("Logowanie nieudane. Spróbuj ponownie.\n")
            client.disconnect()

    # 3. Main Menu Loop
    try:
        while client.get_state() == STATE_AUTHENTICATED:
            print_menu()
            choice = input("Wybierz opcję (1-3): ").strip()
            
            if choice == "1":
                filepath = input("Podaj ścieżkę do pliku lokalnego: ").strip()
                if not filepath:
                    print("Ścieżka do pliku nie może być pusta.")
                    continue
                
                # Strip quotes if dragged-and-dropped in terminal
                filepath = filepath.strip('"').strip("'")
                
                print(f"⏳ Rozpoczynanie wysyłania pliku: {filepath}...")
                success = client.upload_file(filepath)
                if success:
                    print("Plik został pomyślnie wysłany!")
                else:
                    print("Błąd wysyłania pliku.")

            elif choice == "2":
                filename = input("Podaj nazwę pliku na serwerze: ").strip()
                if not filename:
                    print("Nazwa pliku nie może być pusta.")
                    continue
                
                dest_path = input("Podaj lokalną ścieżkę zapisu (np. pobrane.pdf): ").strip()
                if not dest_path:
                    print("Ścieżka zapisu nie może być pusta.")
                    continue
                
                dest_path = dest_path.strip('"').strip("'")
                
                # Resolve path target for nice printing
                target_path = Path(dest_path)
                if dest_path.endswith("/") or dest_path.endswith("\\") or target_path.is_dir() or target_path.suffix == "":
                    target_path = target_path / filename
                
                print(f"⏳ Rozpoczynanie pobierania pliku '{filename}' do '{target_path.resolve()}'...")
                success = client.download_file(filename, dest_path)
                if success:
                    print(f"Plik został pomyślnie zapisany w: {target_path.resolve()}")
                else:
                    print("Błąd pobierania pliku.")

            elif choice == "3":
                print("⏳ Wylogowywanie...")
                client.logout_and_exit()
                print("👋 Do widzenia!")
                break
                
            else:
                print("Nieprawidłowy wybór. Wybierz opcję od 1 do 3.")

    except KeyboardInterrupt:
        print("\n⚠️ Wykryto Ctrl+C. Wychodzenie pomyślnie...")
        client.logout_and_exit()
    except Exception as e:
        logger.error(f"Nieoczekiwany błąd aplikacji: {e}", exc_info=True)
        client.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureShare CLI Client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Adres hosta serwera")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Port serwera")
    args = parser.parse_args()

    run_interactive_cli(args.host, args.port)
