import os
import sys
import subprocess
from pathlib import Path

def find_script(repo_path, script_name):
    """Recursively search for the named script file within the repository."""
    for root, _, files in os.walk(repo_path):
        if script_name in files:
            return Path(root) / script_name
    raise FileNotFoundError(f"Script '{script_name}' not found in repository '{repo_path}'.")

#def create_bat_file(script_name, repo_path, bat_file_path):
def create_bat_file(script_path, bat_file_path):
    """Create or update the batch file to run the Python script."""
    with open(f"{bat_file_path}", "w") as bat_file:
        bat_file.write(f"@echo off\n")
        bat_file.write(f"REM batch file to run {script_path.name} (auto-generated by {Path(__file__).name})\n")
        bat_file.write(f"cd /d {script_path.parent}\n")
        bat_file.write(f"pythonw {script_path.name}\n")

def add_to_startup(bat_file_path):
    """Add the batch file to the Windows Startup folder."""
    startup_folder = Path(os.getenv('APPDATA')) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup_bat_path = startup_folder / "my_script_startup.bat"
    startup_bat_path.write_text(bat_file_path.read_text())

def start_script_as_daemon(bat_file_path):
    """Run the script as a background process."""
    subprocess.Popen([str(bat_file_path)], creationflags=subprocess.CREATE_NO_WINDOW)

def main():
    # Variables
    repo_path = Path(__file__).parent.parent.parent.resolve()
    script_name = "signs_of_life.py"  # Replace with the actual Python script name
    bat_file_name = "start_daemon.bat"
    #bat_file_path = repo_path / "daemon_scripts/windows/start_daemon.bat"

    # Find the script path
    script_path = find_script(repo_path, script_name)
    print(f"Found script at: {script_path}")

    # Find and re-write the batch file path
    bat_file_path = find_script(repo_path, bat_file_name)
    create_bat_file(script_path, bat_file_path)
    print(f"Batch file created at: {bat_file_path}")
    
    # Add the batch file to startup
    #add_to_startup(bat_file_path)
    #print(f"Added batch file to startup folder.")
    
    # Start the script as a daemon
    #start_script_as_daemon(bat_file_path)
    #print(f"Script started as a daemon.")

if __name__ == "__main__":
    main()
