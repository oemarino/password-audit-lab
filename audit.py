import hashlib
import time
from pathlib import Path


def sha256_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_hashes(file_path):
    users = {}
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line and ":" in line:
                username, password_hash = line.split(":", 1)
                users[username] = password_hash
    return users


def load_wordlist(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def save_report(results, total_users, cracked_count, attempts, elapsed_time):
    with open("report.txt", "w", encoding="utf-8") as file:
        file.write("=== Password Audit Report ===\n")
        file.write("Authorized offline educational use only.\n\n")

        for line in results:
            file.write(line + "\n")

        crack_rate = 0
        if total_users > 0:
            crack_rate = (cracked_count / total_users) * 100

        file.write("\n=== Summary ===\n")
        file.write("Users audited: " + str(total_users) + "\n")
        file.write("Passwords matched: " + str(cracked_count) + "\n")
        file.write("Crack rate: " + str(round(crack_rate, 2)) + "%\n")
        file.write("Total guesses attempted: " + str(attempts) + "\n")
        file.write("Elapsed time: " + str(round(elapsed_time, 4)) + " seconds\n")


def audit_passwords(hash_file, wordlist_file):
    stored_hashes = load_hashes(hash_file)
    wordlist = load_wordlist(wordlist_file)

    print("=== Password Audit Lab ===")
    print("Authorized offline educational use only.\n")

    start = time.time()
    cracked = {}
    attempts = 0
    results = []

    for username, target_hash in stored_hashes.items():
        found = False

        for candidate in wordlist:
            attempts += 1
            if sha256_hash(candidate) == target_hash:
                cracked[username] = candidate
                result_line = "[WEAK] " + username + " -> " + candidate
                results.append(result_line)
                print(result_line)
                found = True
                break

        if not found:
            result_line = "[OK]   " + username + " -> no match found"
            results.append(result_line)
            print(result_line)

    end = time.time()

    total_users = len(stored_hashes)
    cracked_count = len(cracked)
    elapsed_time = end - start

    crack_rate = 0
    if total_users > 0:
        crack_rate = (cracked_count / total_users) * 100

    print("\n=== Summary ===")
    print("Users audited:", total_users)
    print("Passwords matched:", cracked_count)
    print("Crack rate:", round(crack_rate, 2), "%")
    print("Total guesses attempted:", attempts)
    print("Elapsed time:", round(elapsed_time, 4), "seconds")

    save_report(results, total_users, cracked_count, attempts, elapsed_time)
    print("\nReport saved as report.txt")


if __name__ == "__main__":
    if not Path("hashes.txt").exists():
        print("Missing hashes.txt")
    elif not Path("wordlist.txt").exists():
        print("Missing wordlist.txt")
    else:
        audit_passwords("hashes.txt", "wordlist.txt")