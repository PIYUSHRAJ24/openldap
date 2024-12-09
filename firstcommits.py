import os
import re
from git import Repo

# Configurable parameters
repo_path = "."  # Path to the Git repository, "." for current directory
branch_name = "develop"  # Branch to analyze
output_file = "version_old.txt"  # Single output file for all version history

def parse_version(version_str):
    """
    Parse version string, handling potential suffixes like '-1', '-2'.
    Ensure proper format and provide a default fallback if parsing fails.
    """
    # Remove any suffix like '-1', '-2'
    base_version = version_str.split('-')[0]

    # Ensure it starts with 'ver'
    if not base_version.startswith('ver'):
        base_version = f"ver{base_version.lstrip('v')}"

    try:
        # Extract and split version numbers
        major, minor, patch = map(int, re.findall(r'\d+', base_version)[:3])
        return f"ver{major}.{minor}.{patch}"
    except (ValueError, IndexError):
        # Fallback to default version if parsing fails
        return "ver0.0.0"


def increment_version(version):
    """
    Increment version number with custom rules:
    - Increment patch first.
    - Every 10 patches increments minor version.
    - Every 10 minor versions increments major version.
    """
    # Parse the current version (validate and sanitize it)
    sanitized_version = parse_version(version)

    try:
        # Split the sanitized version string into components
        major, minor, patch = map(int, sanitized_version[3:].split('.'))

        # Increment patch
        patch += 1

        # Check if we need to increment minor version
        if patch >= 10:
            patch = 0
            minor += 1

        # Check if we need to increment major version
        if minor >= 10:
            minor = 0
            major += 1

        return f"ver{major}.{minor}.{patch}"
    except (ValueError, IndexError):
        # Fallback in case of unexpected errors
        return "ver0.0.0"


def get_repo_history(repo_path, branch_name):
    try:
        repo = Repo(repo_path)
        if repo.bare:
            raise Exception("The repository is not initialized.")

        # Ensure branch exists
        if branch_name not in repo.branches:
            raise Exception(f"Branch '{branch_name}' not found in the repository.")

        # Switch to the branch
        repo.git.checkout(branch_name)

        # Get all commits in the branch
        commits = list(repo.iter_commits(branch_name))

        # Start with the first commit
        current_version = "ver0.0.0"
        version_commits = []
        version_count = {}

        # Iterate through commits in chronological order
        for commit in reversed(commits):  # Reverse for chronological order
            # Check for explicit version in commit message
            version_match = re.search(r'ver?\d+\.\d+\.\d+', commit.message)

            if version_match:
                # Use version from commit message
                potential_version = version_match.group(0)
                current_version = parse_version(potential_version)
            else:
                # Auto-increment version
                current_version = increment_version(current_version)

            # Ensure unique version by appending a counter if needed
            base_version = current_version
            counter = version_count.get(current_version, 0) + 1
            version_count[current_version] = counter

            if counter > 1:
                current_version = f"{base_version}-{counter}"

            # Check for merge commits
            is_merge = len(commit.parents) > 1

            # Prepare commit details
            commit_details = {
                "version": current_version,
                "commit": {
                    "revision": commit.hexsha[:7],
                    "author": commit.author.name,
                    "date": commit.committed_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                    "message": commit.message.strip(),
                    "is_merge": is_merge
                }
            }

            version_commits.append(commit_details)

        return version_commits
    except Exception as e:
        print(f"Error: {e}")
        return []

def write_version_file(version_commits, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        # Reverse the list to show latest version first
        for version_info in reversed(version_commits):
            version = version_info['version']
            commit = version_info['commit']

            # Write header
            file.write(f"------------- {version} ------------------\n")
            file.write(f"Version: {version}\n")
            file.write(f"Merge Commit: {'Yes' if commit['is_merge'] else 'No'}\n\n")

            # Write commit details
            file.write("Commit Details:\n")
            file.write(f"- Revision: {commit['revision']}\n")
            file.write(f"- Author: {commit['author']}\n")
            file.write(f"- Date: {commit['date']}\n")
            file.write(f"- Message: {commit['message']}\n\n")

        print(f"Version history written to {output_file}")

def main():
    version_commits = get_repo_history(repo_path, branch_name)
    if version_commits:
        write_version_file(version_commits, output_file)

if __name__ == "__main__":
    main()
