from flask import Blueprint, flash, redirect, url_for
from pathlib import Path
import os
import sys
import subprocess
from libs.security import admin_required

python_path = sys.executable
systemd_bp = Blueprint('systemd', __name__)

@systemd_bp.route('/create_noc_service', methods=['POST'])
@admin_required
def create_noc_service():   
    service_path = '/etc/systemd/system/noc.service'

    if Path(service_path).exists():
        flash('Service file already exists.', 'info')
        return redirect(url_for('dashboard'))

    try:
        project_dir = Path(__file__).resolve().parent.parent
        script_path = project_dir / 'noc.py'

        content = f"""[Unit]
Description=NOC Service
After=network.target

[Service]
ExecStart={python_path} {script_path}
WorkingDirectory={project_dir}
Restart=always
User=root
Group=root
StandardOutput=append:/var/log/noc.log
StandardError=append:/var/log/noc_error.log

[Install]
WantedBy=multi-user.target
"""

        with open(service_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'noc.service'], check=True)

        flash('noc.service created successfully.', 'success')
    except Exception as e:
        flash(f'Failed to create service file: {e}', 'danger')

    return redirect(url_for('dashboard'))
