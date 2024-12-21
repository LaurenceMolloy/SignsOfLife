# Licence Information

I am pleased to offer this solution freely for personal use, in perpetuity, as my contribution to care in the community. If you are interested in developing a commercial product based on this repository, feel free to reach out. I am available for consultancy work, or we can arrange a licensing agreement.

If you find this project helpful and would like to show your appreciation, you can buy me a coffee at https://ko-fi.com/laurencemolloy

Thank you for your support

# SignsOfLife (User Activity Monitor)

This project monitors user activity on a computer and sends email notifications when no user activity is detected for a specified period and also when user activity resumes. It tracks both keyboard and mouse events and triggers alerts accordingly.

This project is not designed for employee surveillance. Instead, it is intended as a passive health monitoring solution for individuals who live alone and spend significant time on their PC. Inspired by the need to ensure the well-being of a remote-working relative, it provides peace of mind by detecting inactivity and notifying friends or neighbours to check in, should something unexpected have happened.

## Features
- Monitors user activity in real-time (keyboard and mouse).
- Sends email notifications if the user is inactive for a set duration (e.g. 1 hour).
- Sends email notifications whenever the user becomes active again ('waking' state).
- State management for tracking activity status (`active`, `inactive`, `waking`).
- Configurable inactivity check interval and email recipient.
- Can be easily customized to fit personal needs.

## How it Works
- The script continuously checks for user input (keyboard and mouse activity) during specified hours of the day (default: 9am-6pm).
- If no activity is detected for a specified duration (default: 1 hour), an email is sent.
- The system enters a "waking" state if activity is detected after being inactive and sends a "waking" notification.

## Setup
### 1. Clone this repository:
   ```
   git clone https://github.com/LaurenceMolloy/SignsOfLife.git
   ```
### 2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```
### 3. Update the script with your email credentials:
   - Set your email address (`EMAIL_ADDRESS`) and password (`EMAIL_PASSWORD`).
   - Set the recipient's email (`RECIPIENT_EMAIL`).
### 4. (TESTING) Run the script:
   ```
   python signs_of_life.py
   ```
### 5. (PRODUCTION) Set up as a scheduled task or system service to run on startup:
   - Windows: Use Task Scheduler to run the script at startup.
   - Linux/macOS: Set up a cron job or use systemd to run the script automatically when the system starts.


# CICD

Combine_states.py runs every 30 minutes via CI/CD (see combine_states.yml in the .github/workflows folder). It aggregates heartbeats and statuses from all monitored devices, updates data/heartbeat.txt and data/state.txt, and sends email alerts for any changes, reporting lost/recovered communication with devices and user activity (the vital “signs of life” metric).

Testing shows the process takes about 20 seconds of CI/CD runner time per run. At 30-minute intervals, this amounts to roughly 500 minutes per month. With GitHub providing 2000 free CI/CD minutes monthly, this should comfortably fit within your free allowance - assuming light CI/CD usage elsewhere.

# Changing the timings

This solution was developed to monitor a relative who works from home, ensuring timely response while minimizing false alarms. Regular activity checks help improve reaction times without generating unnecessary alerts.  

If your use case differs - such as monitoring a device that is used less frequently - you can adjust the timing settings to reduce false alarms.  

### Key Variables to Modify  

To customize the check and alert intervals, adjust the following variables:  

- **`CHECK_INTERVAL_SECONDS`**  
- **`ALERT_INTERVAL_SECONDS`**  

### Where to Update These Variables  

You will need to modify these settings in two locations:  

- Client: **Local `.env` file**  
- Server: **GitHub Repository Environment Variables**  

**To update GitHub environment variables:**  

1. Go to **Settings** in your GitHub repository.  
2. Navigate to **Secrets & Variables > Actions**.  
3. Select the **Variables** tab.  
4. Update the relevant variables in the **Environment Variables** table.  

### Recommended Configuration  

For optimal performance, set the **`CHECK_INTERVAL_SECONDS`** to **1/3 or 1/4** of the **`ALERT_INTERVAL_SECONDS`**. This ensures multiple checks will occur between repository updates, increasing accuracy without overloading the system.  


# Building a solution for other devices

The current solution is designed for desktops and laptops. Expanding to include mobile devices and tablets is a future possibility, requiring the development of Android and iOS versions of signs_of_life.py.

The Android solution would need to:

 - Assess user activity state every 5 minutes.
 - Maintain a local state.
 - Commit changes to data/states/state_xxx.txt and data/heartbeats/heartbeat_xxx.txt to the designated GitHub repository every 15 minutes.

xxx represents your device ID and must be unique within your device estate.

User activity state is evaluated over the past 15 minutes. If any activity is detected during this window, the state is "active"; otherwise, it is "inactive."

 - state.txt must contain either "active" or "inactive".
 - heartbeat.txt must contain a timestamp only.

I welcome pull requests that add Android or Apple iOS signs-of-life monitoring capabilities to the repository.


# Github PAT 

User Icon - top right
Developer Settings
Personal Access Tokens  - Fine Grained
Set for individual repo (SignsOfLife)
Permissions:
 - Read access to metadata (mandatory)
 - Read and Write access to code (required to push status updates to repo)

