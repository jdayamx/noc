from flask import Blueprint, flash, redirect, request
from pathlib import Path
import os

systemd_bp = Blueprint('systemd', __name__)

@systemd_bp.route('/create_noc_service')
def create_noc_service():
    service_path = '/etc/systemd/system/noc.service'

    if Path(service_path).exists():
        flash('Service file already exists.', 'info')
        return redirect(request.referrer or '/')

    try:
        project_dir = Path(__file__).resolve().parent
        script_path = project_dir / 'noc.py'

        content = f"""[Unit]
Description=NOC Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 {script_path}
WorkingDirectory={project_dir}
Restart=always
User=root
Group=root
StandardOutput=append:/var/log/noc.log
StandardError=append:/var/log/noc_error.log

[Install]
WantedBy=multi-user.target
"""

        with open(service_path, 'w') as f:
            f.write(content)
        os.system('systemctl daemon-reload')

        flash('noc.service created successfully.', 'success')
    except Exception as e:
        flash(f'Failed to create service file: {e}', 'danger')

    return redirect(request.referrer or '/')