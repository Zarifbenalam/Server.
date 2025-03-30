# Relay Server for Replit - Deployment Guide

This guide provides detailed steps to deploy the WebSocket relay server from your local machine to Replit using GitHub.

**Prerequisites:**

*   **Git:** Ensure you have Git installed on your local machine. ([Download Git](https://git-scm.com/downloads))
*   **GitHub Account:** You need a GitHub account. ([Sign up for GitHub](https://github.com/join))
*   **Replit Account:** You need a Replit account. ([Sign up for Replit](https://replit.com/signup))
*   **Project Files:** You should have the following files in your project directory:
    *   `server.py`
    *   `requirements.txt`
    *   `.replit`
    *   `.env.example`
    *   (Optional but recommended) `.gitignore` (see Step 2 below)

---

## Step 1: Initialize Local Git Repository

If you haven't already, initialize a Git repository in your project directory.

1.  **Open a Terminal or Command Prompt:** Navigate to your project's root directory (where `server.py` is located).
2.  **Initialize Git:**
    ```bash
    git init
    ```

## Step 2: Create a `.gitignore` File (Recommended)

Create a file named `.gitignore` in your project's root directory. This tells Git which files or directories to ignore, preventing sensitive or unnecessary files from being uploaded to GitHub.

```gitignore
# .gitignore

# Python cache files
__pycache__/
*.pyc
*.pyo
*.pyd

# Environment files (NEVER commit your actual .env file)
.env

# Database file (optional, depends if you want history)
# relay_server.db

# Log files
*.log

# Backup directory
backups/

# IDE / Editor specific files
.vscode/
.idea/
*.swp
*.swo
```

## Step 3: Add and Commit Files Locally

Add the project files to Git's tracking and create your first commit.

1.  **Stage Files:**
    ```bash
    git add server.py requirements.txt .replit .env.example README.md .gitignore
    # If you have other necessary files, add them too.
    ```
2.  **Commit Files:**
    ```bash
    git commit -m "Initial commit of relay server for Replit deployment"
    ```

## Step 4: Create a New GitHub Repository

1.  **Go to GitHub:** Log in to your GitHub account.
2.  **Create Repository:** Click the "+" icon in the top-right corner and select "New repository".
3.  **Repository Name:** Choose a name (e.g., `replit-relay-server`).
4.  **Description:** Add an optional description.
5.  **Public/Private:** Choose whether the repository should be public or private. Replit can import both.
6.  **Initialize:** **Do NOT** initialize the repository with a README, .gitignore, or license on GitHub if you've already created them locally. Keep it empty for now.
7.  **Click "Create repository".**

## Step 5: Link Local Repository to GitHub and Push

GitHub will show you instructions after creating the repository. Follow the steps for "push an existing repository from the command line".

1.  **Add Remote:** Copy the command provided by GitHub to link your local repository to the remote one. It will look like this (replace `<YourUsername>` and `<YourRepositoryName>`):
    ```bash
    git remote add origin https://github.com/<YourUsername>/<YourRepositoryName>.git
    ```
2.  **Verify Remote (Optional):**
    ```bash
    git remote -v
    ```
    (This should show the `origin` URL you just added).
3.  **Rename Branch (if needed):** GitHub's default branch is often `main`. If your local default branch is `master`, you might want to rename it:
    ```bash
    git branch -M main
    ```
4.  **Push to GitHub:** Push your local `main` (or `master`) branch to GitHub:
    ```bash
    git push -u origin main
    # Or: git push -u origin master
    ```
    You might be prompted for your GitHub username and password (or a personal access token).

Your code is now on GitHub!

## Step 6: Import Repository into Replit

1.  **Go to Replit:** Log in to your Replit account.
2.  **Create Repl:** Click the "+" button (Create Repl) or go to [replit.com/new](https://replit.com/new).
3.  **Import from GitHub:** Select the "Import from GitHub" option on the right.
4.  **Connect GitHub (if needed):** If you haven't connected Replit to your GitHub account, you'll be prompted to authorize it.
5.  **Select Repository:** Find and select the GitHub repository you just created (e.g., `replit-relay-server`).
6.  **Language:** Replit should automatically detect Python.
7.  **Click "Import from GitHub".** Replit will clone your repository and set up the environment.

## Step 7: Configure Replit Secrets

This is a crucial step to provide your server with the necessary configuration without hardcoding it or committing sensitive information.

1.  **Open Secrets:** In your new Repl, click the "Secrets" icon (looks like a padlock) in the left sidebar.
2.  **Add Secrets:** For **each** variable listed in your `.env.example` file:
    *   Enter the variable name (e.g., `PORT`) in the "Key" field.
    *   Enter the desired value (e.g., `8765`) in the "Value" field.
    *   Click "Add new secret".
3.  **IMPORTANT:**
    *   **`JWT_SECRET`:** Generate a strong, random string for this. You can use an online generator or run `python -c "import secrets; print(secrets.token_hex(32))"` in a local terminal.
    *   **`ENCRYPTION_KEY`:** Generate another strong, random key. You can use `python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"`.
    *   **`HOST`:** Set this to `0.0.0.0`. Replit requires this for external accessibility.
    *   **`PORT`:** You can set a specific port (like `8765`), or Replit might assign one automatically if you don't set it (your script reads `os.getenv('PORT', 8765)`). Check Replit's behavior if you omit it.
    *   Review other values like `MAX_CONNECTIONS` based on your Replit plan's limits.
    *   Leave `SSL_CERT_PATH` and `SSL_KEY_PATH` blank unless you are managing your own custom domain and certificates (advanced).

## Step 8: Run the Server on Replit

1.  **Dependencies:** Replit usually installs dependencies from `requirements.txt` automatically upon first run or import. If you encounter import errors, open the "Shell" tab in Replit and run:
    ```bash
    pip install -r requirements.txt
    # or potentially: poetry install (if Replit uses poetry)
    ```
2.  **Run:** Click the big "Run ▶" button at the top center of the Replit interface.
3.  **Console Output:** Replit will execute the `run` command specified in your `.replit` file (`python server.py`). You should see the server's startup messages and logs in the Replit "Console" tab.
4.  **Webview/URL:** Replit will open a "Webview" tab showing the application's output (if it were a web server). For a WebSocket server, this might just show "Not Found" or similar, which is okay. The important part is the public URL Replit provides, usually in the format `https://<repl-name>.<username>.repl.co`. Your WebSocket clients will connect to this URL using the `wss://` protocol (e.g., `wss://<repl-name>.<username>.repl.co`).

## Step 9: Connecting Clients

*   Configure your WebSocket clients to connect to the Replit URL using `wss://`. For example: `wss://replit-relay-server.yourusername.repl.co`.
*   Ensure your client handles the authentication flow defined in `server.py` (sending the initial `auth` message).

## Troubleshooting & Tips

*   **Logs:** Check the Replit "Console" for any error messages during startup or runtime.
*   **Secrets:** Double-check that all required secrets are set correctly and match the names expected by `server.py`.
*   **Dependencies:** Ensure all packages in `requirements.txt` were installed correctly. Use the "Shell" tab to manage packages if needed (`pip list`, `pip install ...`).
*   **Host/Port:** Verify `HOST` is `0.0.0.0` in Secrets. The port might be managed by Replit.
*   **Replit Resources:** Free Replit plans have limitations on CPU, RAM, storage, and network egress. If your server experiences issues under load, you might be hitting these limits.
*   **Updates:** To update the deployed code, push changes to your GitHub repository, then go to your Repl, navigate to the "Version Control" tab (Git icon), and click "Pull" to fetch and apply the latest changes from GitHub. You may need to restart the Repl ("Stop" then "Run").