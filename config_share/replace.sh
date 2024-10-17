#!/bin/bash
python_version=3.12
file_path="/usr/local/lib/python${python_version}/http/server.py"
#file_path="/usr/local/lib/python3.12/http/server.py"
target_line="self.send_header('Server', self.version_string())"
replacement_line="self.send_header('Server', 'DigiLocker')"
backup_file="${file_path}.bak"

if [[ -f "$file_path" ]]; then
    # Create a backup of the original file
    cp "$file_path" "$backup_file"
    echo "Backup created at $backup_file"

    # Use sed to find and replace the line
    sed -i "s|$target_line|$replacement_line|" "$file_path"
    
    if [[ $? -eq 0 ]]; then
        echo "Line successfully replaced in $file_path"
    else
        echo "Error: Failed to replace the line"
    fi
else
    echo "Error: File $file_path not found."
fi
