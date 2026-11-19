# First GitHub push and sharing with friends

ConfigShield AI is a local Kubernetes security review assistant: automatic supported-YAML inspection, seven selected Checkov checks, reviewed guidance, editable application requirements, optional Gemini suggestions, approval-gated candidates, independent verification, and local downloads. It does not train Gemini, deploy workloads, or prove runtime compatibility.

Suggested GitHub repository description:

> Kubernetes security review assistant with Checkov, grounded Gemini suggestions, application-requirement checks, and independent YAML verification.

## Create an empty GitHub repository

Sign in to GitHub and create `configshield-ai`. Choose visibility; private sharing requires giving friends access. Leave automatic README, .gitignore, and license initialization unchecked because local files already exist. Select a project license only when you have made that choice; none is implied by this guide.

The supplied external KustomizeGoat ZIP did not contain a license file. Its attribution and checksums are recorded under `samples/external/`; review upstream reuse terms before public redistribution. Public visibility is a separate decision from letting invited friends view a private repository.

## Connect and push this workspace

The checked workspace was already initialized, with branch `master`, no origin remote, and no commits. Replace the name, email, and GitHub username placeholders before running. The email is commit metadata; choose your GitHub no-reply address if preferred. These commands have not been run for you.

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai

git config user.name "YOUR NAME"
git config user.email "YOUR GITHUB EMAIL"
git branch -M main

git add .
git status
git diff --cached --stat
git ls-files backend/.env
```

`git ls-files backend/.env` must print nothing. Review the staged list; virtual environments, `.env`, node_modules, tool binaries, builds, generated evaluation results, and browser artifacts should not be staged. The `.env.example` template is intended to be included. Do not use `git add -f` to override these exclusions.

After reviewing, commit and connect the empty remote:

```powershell
git commit -m "Build ConfigShield AI Kubernetes security review MVP"
git remote add origin https://github.com/YOUR_USERNAME/configshield-ai.git
git remote -v
git push -u origin main
```

Sign in through the Git credential helper/browser if prompted. Do not put an API key or GitHub token into the remote URL. If Git asks for HTTPS password-style authentication, use GitHub's supported token/credential-helper flow, not your Gemini key. See [GitHub's first-push guide](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github) and [remote management](https://docs.github.com/en/get-started/git-basics/managing-remote-repositories).

If origin already exists on a later attempt, inspect `git remote -v`; update it with `git remote set-url origin https://github.com/YOUR_USERNAME/configshield-ai.git` when appropriate. Do not force-push to bypass a rejected push. A remote containing existing commits requires reviewing and reconciling those commits first.

| Command | Meaning |
| --- | --- |
| `git config user.name` / `user.email` | Set this repository's commit author metadata; this does not sign in to GitHub |
| `git branch -M main` | Rename the local branch to main |
| `git add .` | Stage non-ignored files under the current project folder |
| `git status` / `git diff --cached --stat` | Review what the next commit will contain |
| `git ls-files backend/.env` | Check whether the secret file has accidentally become tracked |
| `git commit -m "..."` | Save a local version of the staged files |
| `git remote add origin ...` | Name the GitHub repository connection origin |
| `git remote -v` | Show the configured fetch/push destination |
| `git push -u origin main` | Upload commits and remember the default remote branch |

## What friends do

Install Git, Python 3.12, and a compatible Node.js version (the project was tested on Node 24.14.0). Then:

```powershell
git clone https://github.com/YOUR_USERNAME/configshield-ai.git
cd configshield-ai
```

Follow the root README's **Install**, **Start locally**, and **First demonstration, with no API key** sections. Python/scanner environments, npm packages, and validator binaries are recreated locally rather than pushed to Git. The controlled cases and supported external input are included; they do not need the original ZIP or your private API key. Live Gemini requires each developer to configure their own backend key/free-tier confirmation. Windows is the verified target; other operating systems need adapted venv/tool paths and independent verification.

Share the repository page URL, not your `.env`. The README appears on GitHub's project page and supplies project context, scope, dependencies, usage, architecture, limitations, and documentation links.

## Later changes

From the project root, review and commit intentional changes:

```powershell
git status
git add .
git diff --cached --stat
git commit -m "Describe the change"
git push
```

Friends who only need the latest version can use `git pull --ff-only` in a clean checkout. This stops instead of merging diverged local changes automatically. Review local work before updating.
